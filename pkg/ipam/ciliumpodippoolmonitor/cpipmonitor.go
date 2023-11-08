// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumpodippoolmonitor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
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
	poolAdd                   = "PoolAdd"
	poolUpdate                = "PoolUpdate"
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
	intfIndex   int
	ruleTableID int
}

type routeOperationInfo struct {
	// adding/updating network
	addedCIDRStr string
	addedNetwork *net.IPNet

	eniNetMap map[int]eniInfo4Route

	// addedNetWork in eniNetMap
	existNetwork *eniInfo4Route

	defaultRuleTable         int
	defaultIntfIndex         int
	controlPlaneDefaultRoute netlink.Route
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
	routeChange(obj, poolAdd)
}

func onUpdate(oldObj, newObj interface{}) {
	//oldCiliumPodIPPool := oldObj.(*v2alpha1.CiliumPodIPPoolList)
	//newCiliumPodIPPool := newObj.(*v2alpha1.CiliumPodIPPoolList)
	routeChange(newObj, poolUpdate)

}

func onDelete(obj interface{}) {
	var operationInfo *routeOperationInfo
	var err error

	if operationInfo, err = getInfo4RouteConf(obj); err != nil {
		log.Errorf("Can not process Delete Operation: %s", err)
		return
	}
	// ip route del ........ table [default table id]
	netlink.RouteDel(&netlink.Route{
		LinkIndex: operationInfo.defaultIntfIndex,
		Dst:       operationInfo.addedNetwork,
		Table:     operationInfo.defaultRuleTable,
		Protocol:  linux_defaults.RTProto,
	})

	// delete all entry in this table
	if operationInfo.existNetwork != nil {
		// if do optimize strategy in func routeChange()
		// must: ip rule del from all to [network] lookup [witheni-tableID] priority 300
		route.DeleteRouteTable(operationInfo.existNetwork.ruleTableID, netlink.FAMILY_V4)
	}
	// ip rule del from all to  [network] lookup [11] priority 300 // ingress using default table
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

	// ip rule add from all to [addedNetwork] lookup [defaultRuleTable] priority 300 // ingress using default table
	if err = route.ReplaceRule(route.Rule{
		//Priority: linux_defaults.RulePriorityIngress,
		Priority: linux_defaults.RulePriorityHostLegacyRoutingCase,
		To:       operationInfo.addedNetwork,
		Table:    operationInfo.defaultRuleTable,
		Protocol: linux_defaults.RTProto,
	}); err != nil {
		log.Errorf("unable to install ip rule: %s", err)
	}
	// add every network to default route table
	// netlink.Replace(&routeRule): err:network is down
	// ip route add [addedNetwork] dev [default IntfName] proto kernel table [defaultRuleTable]
	var defaultLink netlink.Link
	defaultLink, _ = netlink.LinkByIndex(operationInfo.defaultIntfIndex)
	//avoid: Error: Device for nexthop is not up
	netlink.LinkSetUp(defaultLink)
	cmdStr := fmt.Sprintf("ip route add %s dev %s proto kernel table %d",
		operationInfo.addedCIDRStr, defaultLink.Attrs().Name, operationInfo.defaultRuleTable)
	log.Debugf("====route value:%v", cmdStr)
	command := exec.Command("bash", "-c", cmdStr)
	v1, v2 := command.CombinedOutput()
	log.Debugf("====route add output:%v,error: %v", string(v1), v2)

	for _, eniInfo := range operationInfo.eniNetMap {
		// Optimize in the future
		// ip rule del from all to [nework] lookup [default table id]

		// ip rule add from all to [network] lookup [eniInfo.ruleTableID]

		// ip route add network dev [eni IntfName]

		// avoid: Error: Device for nexthop is not up

		// add default route for reboot
		addRouteToDesignatedTable(eniInfo.ruleTableID, &operationInfo.controlPlaneDefaultRoute)
		log.Debugf("=======default route info:%v", operationInfo.controlPlaneDefaultRoute)
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
			einfo.intfIndex, err = linuxrouting.RetrieveIfaceIndexFromMAC(eni.MAC)
			eniNetMap[intfNum] = einfo
			intfNums = append(intfNums, intfNum)

			if cidrStr == eni.Subnet.CIDR {
				//eg. 171      142,168,113,17
				routeOperation.existNetwork = &einfo
			}
		} else {
			// get control plan eni for defaul route
			ctrlIntfIndex, _ := linuxrouting.RetrieveIfaceIndexFromMAC(eni.MAC)
			ctrlIntfLink, _ := netlink.LinkByIndex(ctrlIntfIndex)
			ctrlIntfRoutelist, _ := netlink.RouteList(ctrlIntfLink, netlink.FAMILY_V4)
			for _, r := range ctrlIntfRoutelist {
				if r.Dst.IP.Equal(net.IPv4zero) {
					routeOperation.controlPlaneDefaultRoute = r
					break
				}
			}
		}
	}
	sort.Ints(intfNums)
	if len(intfNums) == 0 {
		log.Errorf("enis content:%v", enis)
		err = fmt.Errorf("do not have enough eni info! enis:%d", len(enis))
		return nil, err
	}
	routeOperation.defaultRuleTable = intfNums[0] + linux_defaults.RouteTableInterfacesOffset
	routeOperation.defaultIntfIndex = eniNetMap[intfNums[0]].intfIndex
	routeOperation.eniNetMap = eniNetMap

	return routeOperation, err
}

func addRouteToDesignatedTable(tableID int, route *netlink.Route) error {
	if route == nil {
		log.Errorf("route rule is nil, tableID, tableid[%v]", tableID)
		return fmt.Errorf("passed route rule is nil, tableID, tableid[%v]", tableID)
	}

	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: route.LinkIndex,
		Dst:       route.Dst,
		//Dst:      &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Gw:       route.Gw,
		Table:    tableID,
		Protocol: linux_defaults.RTProto,
	}); err != nil {
		log.Errorf("Add route:%v to table [%d] error", route, tableID)
		return err
	}
	return nil
}
