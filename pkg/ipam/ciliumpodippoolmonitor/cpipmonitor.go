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

type routeOperationInfo struct {
	addedCIDRStr     string
	addedNetwork     *net.IPNet
	eniNetMap        map[int]eniInfo4Route
	existNetwork     *eniInfo4Route
	defaultRuleTable int
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
	// this section can delete, do not cache
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
	routeChange(obj, "PoolAdd")
}

func onUpdate(oldObj, newObj interface{}) {
	//oldCiliumPodIPPool := oldObj.(*v2alpha1.CiliumPodIPPoolList)
	//newCiliumPodIPPool := newObj.(*v2alpha1.CiliumPodIPPoolList)
	routeChange(newObj, "PoolUpdate")

}

func onDelete(obj interface{}) {
	var operationInfo *routeOperationInfo
	var err error

	if operationInfo, err = getInfo4RouteConf(obj); err != nil {
		log.Errorf("Can not process Delete Operation: %s", err)
		return
	}

	for _, eniInfo := range operationInfo.eniNetMap {
		// add route rule across
		//ifindex, err := retrieveIfIndexFromMAC(net.ParseMAC(eni.MAC), mtu)
		// ip route add ........ table tableid
		if operationInfo.addedCIDRStr != eniInfo.strNetwork {
			infIndex, _ := linuxrouting.RetrieveIfaceIndexFromMAC(eniInfo.intfMac)
			netlink.RouteDel(&netlink.Route{
				LinkIndex: infIndex,
				Dst:       operationInfo.addedNetwork,
				Table:     eniInfo.ruleTableID,
				Protocol:  linux_defaults.RTProto,
			})
		}
	}
	// delete all entry in this table
	if operationInfo.existNetwork != nil {
		route.DeleteRouteTable(operationInfo.existNetwork.ruleTableID, netlink.FAMILY_V4)
	}

	// ip rule del from all to 192.168.80.0/24 lookup [11] priority 300 // ingress using default table
	defaultRouteTable := operationInfo.defaultRuleTable
	if err := route.DeleteRule(netlink.FAMILY_V4, route.Rule{
		//Priority: linux_defaults.RulePriorityIngress,
		Priority: linux_defaults.RulePriorityHostLegacyRoutingCase,
		To:       operationInfo.addedNetwork,
		Table:    defaultRouteTable,
		Protocol: linux_defaults.RTProto,
	}); err != nil {
		log.Errorf("unable to install ip rule: %s", err)
	}

}

func routeChange(obj interface{}, operation string) {
	var operationInfo *routeOperationInfo
	var err error

	if operationInfo, err = getInfo4RouteConf(obj); err != nil {
		log.Errorf("Can not process %s Operation: %s", operation, err)
		return
	}

	for _, eniInfo := range operationInfo.eniNetMap {
		//ifindex, err := retrieveIfIndexFromMAC(net.ParseMAC(eni.MAC), mtu)
		// ip route add ........ table tableid [add route rule across]
		if operationInfo.addedCIDRStr != eniInfo.strNetwork {
			infIndex, _ := linuxrouting.RetrieveIfaceIndexFromMAC(eniInfo.intfMac)
			netlink.RouteReplace(&netlink.Route{
				LinkIndex: infIndex,
				Dst:       operationInfo.addedNetwork,
				Table:     eniInfo.ruleTableID,
				Protocol:  linux_defaults.RTProto,
			})

			existedNetwork := operationInfo.existNetwork
			if existedNetwork != nil {
				infIndex, _ = linuxrouting.RetrieveIfaceIndexFromMAC(existedNetwork.intfMac)
				_, network, _ := net.ParseCIDR(eniInfo.strNetwork)
				netlink.RouteReplace(&netlink.Route{
					LinkIndex: infIndex,
					Dst:       network,
					Table:     existedNetwork.ruleTableID,
					Protocol:  linux_defaults.RTProto,
				})
			}
		}
	}
	// ip rule add from all to 192.168.80.0/24 lookup [11] priority 300 // ingress using default table
	defaultRouteTable := operationInfo.defaultRuleTable
	if err := route.ReplaceRule(route.Rule{
		//Priority: linux_defaults.RulePriorityIngress,
		Priority: linux_defaults.RulePriorityHostLegacyRoutingCase,
		To:       operationInfo.addedNetwork,
		Table:    defaultRouteTable,
		Protocol: linux_defaults.RTProto,
	}); err != nil {
		log.Errorf("unable to install ip rule: %s", err)
	}
}

func getInfo4RouteConf(obj interface{}) (*routeOperationInfo, error) {
	var err error

	ciliumPodIPPool := obj.(*v2alpha1.CiliumPodIPPool)
	routeOperation := &routeOperationInfo{}
	routeOperation.addedCIDRStr = ciliumPodIPPool.Spec.CIDR
	cidrStr := routeOperation.addedCIDRStr
	// create -> unuse -> delete : for add
	// create -> used: for update
	if _, routeOperation.addedNetwork, err = net.ParseCIDR(cidrStr); err != nil {
		log.Errorf("unable to parse cidrStr[%v]: %s", cidrStr, err)
		return nil, err
	}

	// kubecte get cn node-x -oyaml
	nodeName := os.Getenv("K8S_NODE_NAME")
	var ciliumNodeContent *v2.CiliumNode
	if ciliumNodeContent, err = ciliumNodeInterface.Get(context.TODO(), nodeName, meta_v1.GetOptions{}); err != nil {
		log.Errorf("Get CiliumNode conetent fail: %s", err)
		return nil, err
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

			if cidrStr == eni.Subnet.CIDR {
				//eg. 171      142,168,113,17
				routeOperation.existNetwork = &einfo
			}
		}
	}
	sort.Ints(intfNums)
	routeOperation.defaultRuleTable = intfNums[0]
	routeOperation.eniNetMap = eniNetMap

	return routeOperation, err
}
