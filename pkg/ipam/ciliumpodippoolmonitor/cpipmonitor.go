// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumpodippoolmonitor

import (
	"context"
	"os"
	"sort"
	"sync"

	"net"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	openStack "github.com/cilium/cilium/pkg/openstack/utils"
	"github.com/vishvananda/netlink"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

var (
	log                       = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-cpip-monitor")
	queueKeyFunc              = cache.DeletionHandlingMetaNamespaceKeyFunc
	ciliumPodIPPoolStore      cache.Store
	ciliumPodIPPoolController cache.Controller
	ciliumNodeInterface       ciliumv2.CiliumNodeInterface
)

type CiliumPodIPPoolMonitor struct {
	CiliumPodIPPoolInterface ciliumv2alpha1.CiliumV2alpha1Interface
	CiliumNodeInterface      ciliumv2.CiliumNodeInterface
	stop                     chan struct{}
	InProgress               map[string]struct{}
	sync.Mutex
}

type eniInfo4Route struct {
	strNetwork  string
	intfMac     string
	ruleTableID int
}

func (m *CiliumPodIPPoolMonitor) Start(ctx hive.HookContext) (err error) {
	ciliumNodeInterface = m.CiliumNodeInterface
	ciliumPodIPPoolStore, ciliumPodIPPoolController = informer.NewInformer(
		utils.ListerWatcherFromTyped[*v2alpha1.CiliumPodIPPoolList](m.CiliumPodIPPoolInterface.CiliumPodIPPools()),
		&v2alpha1.CiliumPodIPPool{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    onAdd,
			UpdateFunc: onUpdate,
			DeleteFunc: onDelete,
		},
		nil,
	)
	go func() {
		ciliumPodIPPoolController.Run(m.stop)
	}()

	cache.WaitForCacheSync(m.stop, ciliumPodIPPoolController.HasSynced)
	return nil
}

func (m *CiliumPodIPPoolMonitor) Stop(ctx hive.HookContext) error {
	m.stop <- struct{}{}
	defer close(m.stop)
	return nil
}

func onAdd(obj interface{}) {
	routeChange(obj)
}

func onUpdate(oldObj, newObj interface{}) {
	//oldCiliumPodIPPool := oldObj.(*v2alpha1.CiliumPodIPPoolList)
	//newCiliumPodIPPool := newObj.(*v2alpha1.CiliumPodIPPoolList)
	routeChange(newObj)

}

func onDelete(obj interface{}) {

}

func routeChange(obj interface{}) {
	var err error
	// Observed a panic:
	//&runtime.TypeAssertionError{_interface:(*runtime._type)(0x2f62780), concrete:(*runtime._type)(0x35a69c0), asserted:(*runtime._type)(0x34888a0), missingMethod:""}
	// (interface conversion: interface {} is *v2alpha1.CiliumPodIPPool, not *v2alpha1.CiliumPodIPPoolList)
	ciliumPodIPPool := obj.(*v2alpha1.CiliumPodIPPool)
	//log.Errorf("#######ciliumPodIPPool#1###%v", ciliumPodIPPool.Spec.CIDR)
	cidrStr := ciliumPodIPPool.Spec.CIDR
	//log.Errorf("#######ciliumPodIPPool####%v+", ciliumPodIPPool.Spec.IPv4.CIDRs) // nil pointer dereference
	//log.Errorf("#######ciliumPodIPPool####%v", ciliumPodIPPool.Spec.IPv4.MaskSize) // nil pointer dereferenc
	// event add may have not cidrStr for updating fill
	var newNetworkInfo *net.IPNet
	if _, newNetworkInfo, err = net.ParseCIDR(cidrStr); err != nil {
		log.Errorf("unable to parse cidrStr[%v]: %s", cidrStr, err)
		return
	}

	//log.Errorf("#######ciliumPodIPPool#ip###%v", ip)             // 192.168.80.0
	//log.Errorf("#######ciliumPodIPPool#net.IP###%v", newNetworkInfo.IP)     // 192.168.80.0
	//log.Errorf("#######ciliumPodIPPool#net.Mask###%v", newNetworkInfo.Mask) // ffffff00
	// route table<--tableID<-- enitag
	//ruleList, _ := netlink.RuleList(netlink.FAMILY_V4)
	nodeName := os.Getenv("K8S_NODE_NAME")
	// kubectl get cn, get tableID
	var ciliumNodeContent *v2.CiliumNode
	if ciliumNodeContent, err = ciliumNodeInterface.Get(context.TODO(), nodeName, meta_v1.GetOptions{}); err != nil {
		log.Errorf("Get CiliumNode conetent fail: %s", err)
		return
	}
	enis := ciliumNodeContent.Status.OpenStack.ENIs
	intfNums := []int{}
	eniNetMap := make(map[int]eniInfo4Route)
	for _, eni := range enis {
		if 0 < len(eni.Tags) {
			intfNum := openStack.GetENIIndexFromTags(eni.Tags)
			einfo := eniInfo4Route{strNetwork: eni.Subnet.CIDR, intfMac: eni.MAC, ruleTableID: intfNum + linux_defaults.RouteTableInterfacesOffset}
			eniNetMap[intfNum] = einfo
			intfNums = append(intfNums, intfNum)
		}
	}

	var reverseNetwork *eniInfo4Route = nil
	for _, eniInfo := range eniNetMap {
		//log.Errorf("### tags #########%v:%v:mac:%v", eni+10, eniInfo.strNetwork, eniInfo.intfMac)
		//eg. 171      142,168,113,17
		if cidrStr == eniInfo.strNetwork {
			reverseNetwork = &eniInfo
		}
	}

	for _, eniInfo := range eniNetMap {
		// add route rule across
		//ifindex, err := retrieveIfIndexFromMAC(net.ParseMAC(eni.MAC), mtu)
		// ip route add ........ table tableid
		if cidrStr != eniInfo.strNetwork {
			infIndex, _ := linuxrouting.RetriveInIndexFromMac(eniInfo.intfMac)
			netlink.RouteReplace(&netlink.Route{
				LinkIndex: infIndex,
				Dst:       newNetworkInfo,
				Table:     eniInfo.ruleTableID,
				Protocol:  linux_defaults.RTProto,
			})

			if reverseNetwork != nil {
				infIndex, _ = linuxrouting.RetriveInIndexFromMac(reverseNetwork.intfMac)
				_, network, _ := net.ParseCIDR(reverseNetwork.strNetwork)
				netlink.RouteReplace(&netlink.Route{
					LinkIndex: infIndex,
					Dst:       network,
					Table:     reverseNetwork.ruleTableID,
					Protocol:  linux_defaults.RTProto,
				})
			}
		}
	}
	// ip rule add from all to 192.168.80.0/24 lookup [11] priority 300 // ingress using default table
	sort.Ints(intfNums)
	if err := route.ReplaceRule(route.Rule{
		//Priority: linux_defaults.RulePriorityIngress,
		Priority: linux_defaults.RulePriorityLegacyHostRoutingCase,
		To:       newNetworkInfo,
		Table:    eniNetMap[intfNums[0]].ruleTableID,
		Protocol: linux_defaults.RTProto,
	}); err != nil {
		log.Errorf("unable to install ip rule: %s", err)
	}
}
