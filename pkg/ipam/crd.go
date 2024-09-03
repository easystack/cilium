// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"fmt"
	ipamMetadata "github.com/cilium/cilium/pkg/ipam/metadata"
	v12 "k8s.io/api/core/v1"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	alibabaCloud "github.com/cilium/cilium/pkg/alibabacloud/utils"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/deviceplugin"
	"github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipam/staticip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	openStack "github.com/cilium/cilium/pkg/openstack/utils"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

var (
	sharedNodeStore *nodeStore
	initNodeStore   sync.Once
)

const (
	fieldName = "name"

	customPool = "ipam.cilium.io/ip-pool"
	ipRecycle  = "eaystack.io/vpc-ip-claim-delete-policy"
)

// nodeStore represents a CiliumNode custom resource and binds the CR to a list
// of allocators
type nodeStore struct {
	// mutex protects access to all members of this struct
	mutex lock.RWMutex

	// ownNode is the last known version of the own node resource
	ownNode *ciliumv2.CiliumNode

	// allocators is a list of allocators tied to this custom resource
	allocators []*crdAllocator

	// refreshTrigger is the configured trigger to synchronize updates to
	// the custom resource with rate limiting
	refreshTrigger *trigger.Trigger

	// allocationPoolSize is the size of the IP pool for each address
	// family
	allocationPoolSize map[Family]int

	// signal for completion of restoration
	restoreFinished  chan struct{}
	restoreCloseOnce sync.Once

	clientset client.Clientset

	conf      Configuration
	mtuConfig MtuConfiguration

	ipsToPool map[string]string

	csipMgr *staticip.Manager

	devicePluginManager           *deviceplugin.ENIIPDevicePlugin
	devicePluginResource          *deviceplugin.Resource
	projectName                   string
	projectLabelGetter            utils.NodeLabelForProjectConfiguration
	metadata                      *ipamMetadata.Manager
	devicePluginServerInitialized bool
}

// newNodeStore initializes a new store which reflects the CiliumNode custom
// resource of the specified node name
func newNodeStore(nodeName string, conf Configuration, owner Owner, clientset client.Clientset, k8sEventReg K8sEventRegister, mtuConfig MtuConfiguration, csipMgr *staticip.Manager, metadata *ipamMetadata.Manager, projectLabelGetter utils.NodeLabelForProjectConfiguration) *nodeStore {
	log.WithField(fieldName, nodeName).Info("Subscribed to CiliumNode custom resource")

	store := &nodeStore{
		allocators:         []*crdAllocator{},
		allocationPoolSize: map[Family]int{},
		conf:               conf,
		mtuConfig:          mtuConfig,
		clientset:          clientset,
		ipsToPool:          map[string]string{},
		metadata:           metadata,
		projectLabelGetter: projectLabelGetter,
	}

	if csipMgr != nil {
		store.csipMgr = csipMgr
	}

	store.restoreFinished = make(chan struct{})

	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "crd-allocator-node-refresher",
		MinInterval: option.Config.IPAMCiliumNodeUpdateRate,
		TriggerFunc: store.refreshNodeTrigger,
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize CiliumNode synchronization trigger")
	}
	store.refreshTrigger = t

	store.devicePluginResource = &deviceplugin.Resource{
		UpdateSignal: make(chan struct{}),
		Count:        0,
	}

	store.devicePluginManager = deviceplugin.NewENIIPDevicePlugin(store.devicePluginResource, context.TODO(), func() int {

		nonDevicePluginCount, err := store.getNonDevicePluginPodCount()
		log.Infof("nonDevicePluginCount: %d", nonDevicePluginCount)
		if err != nil {
			log.Errorf("Failed to get non device plugin pod count: %s", err)
			return 0
		}

		reportCount := store.acquireResourceCount() - nonDevicePluginCount

		return reportCount
	})

	// Create the CiliumNode custom resource. This call will block until
	// the custom resource has been created
	owner.UpdateCiliumNodeResource()
	go func() {

		tick := time.NewTicker(time.Second * 30)
		for {
			select {
			case <-tick.C:
				node, err := clientset.GetK8sNode(context.TODO(), nodeTypes.GetName())
				if err != nil {
					log.Infof("Failed to get local k8s node, error: %s", err)
				} else {
					if p, ok := node.Labels[store.projectLabelGetter.GetNodeLabelForProject()]; ok && p != "" {
						store.projectName = p
						goto serveDevicePlugin
					}
				}

			}
		}
	serveDevicePlugin:
		tick.Stop()
		err := store.devicePluginManager.Serve(store.projectName)
		if err != nil {
			log.Fatalf("Failed to serve device plugin server, error: %s", err)
		}
		store.devicePluginServerInitialized = true
		log.Infof("Device plugin server initialized.")
	}()

	apiGroup := "cilium/v2::CiliumNode"
	ciliumNodeSelector := fields.ParseSelectorOrDie("metadata.name=" + nodeName)
	_, ciliumNodeInformer := informer.NewInformer(
		utils.ListerWatcherWithFields(
			utils.ListerWatcherFromTyped[*ciliumv2.CiliumNodeList](clientset.CiliumV2().CiliumNodes()),
			ciliumNodeSelector),
		&ciliumv2.CiliumNode{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k8sEventReg.K8sEventReceived(apiGroup, "CiliumNode", "create", valid, equal) }()
				if node, ok := obj.(*ciliumv2.CiliumNode); ok {
					valid = true
					store.updateLocalNodeResource(node.DeepCopy())
					k8sEventReg.K8sEventProcessed("CiliumNode", "create", true)
				} else {
					log.Warningf("Unknown CiliumNode object type %s received: %+v", reflect.TypeOf(obj), obj)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k8sEventReg.K8sEventReceived(apiGroup, "CiliumNode", "update", valid, equal) }()
				if oldNode, ok := oldObj.(*ciliumv2.CiliumNode); ok {
					if newNode, ok := newObj.(*ciliumv2.CiliumNode); ok {
						valid = true
						newNode = newNode.DeepCopy()
						for id, v := range newNode.Status.OpenStack.ENIs {
							log.Infof("######### New cilium node %s: eni %s is %+v ", newNode.Name, id, v)
						}
						for id, v := range oldNode.Status.OpenStack.ENIs {
							log.Infof("######### Old cilium node %s: eni %s is %+v ", oldNode.Name, id, v)
						}
						if oldNode.DeepEqual(newNode) {
							// The UpdateStatus call in refreshNode requires an up-to-date
							// CiliumNode.ObjectMeta.ResourceVersion. Therefore, we store the most
							// recent version here even if the nodes are equal, because
							// CiliumNode.DeepEqual will consider two nodes to be equal even if
							// their resource version differs.
							store.setOwnNodeWithoutPoolUpdate(newNode)
							equal = true
							return
						}
						store.updateLocalNodeResource(newNode)
						k8sEventReg.K8sEventProcessed("CiliumNode", "update", true)
					} else {
						log.Warningf("Unknown CiliumNode object type %T received: %+v", oldNode, oldNode)
					}
				} else {
					log.Warningf("Unknown CiliumNode object type %T received: %+v", oldNode, oldNode)
				}
			},
			DeleteFunc: func(obj interface{}) {
				// Given we are watching a single specific
				// resource using the node name, any delete
				// notification means that the resource
				// matching the local node name has been
				// removed. No attempt to cast is required.
				store.deleteLocalNodeResource()
				k8sEventReg.K8sEventProcessed("CiliumNode", "delete", true)
				k8sEventReg.K8sEventReceived(apiGroup, "CiliumNode", "delete", true, false)
			},
		},
		nil,
	)

	go ciliumNodeInformer.Run(wait.NeverStop)

	log.WithField(fieldName, nodeName).Info("Waiting for CiliumNode custom resource to become available...")
	if ok := cache.WaitForCacheSync(wait.NeverStop, ciliumNodeInformer.HasSynced); !ok {
		log.WithField(fieldName, nodeName).Fatal("Unable to synchronize CiliumNode custom resource")
	} else {
		log.WithField(fieldName, nodeName).Info("Successfully synchronized CiliumNode custom resource")
	}

	for {
		minimumReached, required, numAvailable := store.hasMinimumIPsInPool()
		logFields := logrus.Fields{
			fieldName:   nodeName,
			"required":  required,
			"available": numAvailable,
		}
		if minimumReached {
			log.WithFields(logFields).Info("All required IPs are available in CRD-backed allocation pool")
			break
		}

		log.WithFields(logFields).WithField(
			logfields.HelpMessage,
			"Check if cilium-operator pod is running and does not have any warnings or error messages.",
		).Info("Waiting for IPs to become available in CRD-backed allocation pool")
		time.Sleep(5 * time.Second)
	}

	go func() {
		// Initial upstream sync must wait for the allocated IPs
		// to be restored
		<-store.restoreFinished
		store.refreshTrigger.TriggerWithReason("initial sync")
	}()

	return store
}

func deriveVpcCIDRs(node *ciliumv2.CiliumNode) (primaryCIDR *cidr.CIDR, secondaryCIDRs []*cidr.CIDR) {
	if len(node.Status.ENI.ENIs) > 0 {
		// A node belongs to a single VPC so we can pick the first ENI
		// in the list and derive the VPC CIDR from it.
		for _, eni := range node.Status.ENI.ENIs {
			c, err := cidr.ParseCIDR(eni.VPC.PrimaryCIDR)
			if err == nil {
				primaryCIDR = c
				for _, sc := range eni.VPC.CIDRs {
					c, err = cidr.ParseCIDR(sc)
					if err == nil {
						secondaryCIDRs = append(secondaryCIDRs, c)
					}
				}
				return
			}
		}
	}
	if len(node.Status.Azure.Interfaces) > 0 {
		for _, azif := range node.Status.Azure.Interfaces {
			c, err := cidr.ParseCIDR(azif.CIDR)
			if err == nil {
				primaryCIDR = c
				return
			}
		}
	}
	// return AlibabaCloud vpc CIDR
	if len(node.Status.AlibabaCloud.ENIs) > 0 {
		c, err := cidr.ParseCIDR(node.Spec.AlibabaCloud.CIDRBlock)
		if err == nil {
			primaryCIDR = c
			return
		}
	}
	if len(node.Status.OpenStack.ENIs) > 0 {
		// A node belongs to a single VPC so we can pick the first ENI
		// in the list and derive the VPC CIDR from it.
		for _, eni := range node.Status.OpenStack.ENIs {

			// there are more than one subnets for openstack multiple pools
			// always derive the subnet cidr of primary nic as native routing cidr which is used in Configure Routing only for ENI mode
			// returned primary cider will be configured n.conf.SetIPv4NativeRoutingCIDR(primaryCIDR)
			// so that different cidrs will come into fatal error in autoDetectIPv4NativeRoutingCIDR()
			if !openStack.IsExcludedByTags(eni.Tags) {
				continue
			}
			c, err := cidr.ParseCIDR(eni.Subnet.CIDR)
			if err == nil {
				primaryCIDR = c
				return
			}
		}
	}

	return
}

func (n *nodeStore) autoDetectIPv4NativeRoutingCIDR() bool {
	if primaryCIDR, secondaryCIDRs := deriveVpcCIDRs(n.ownNode); primaryCIDR != nil {
		allCIDRs := append([]*cidr.CIDR{primaryCIDR}, secondaryCIDRs...)
		if nativeCIDR := n.conf.GetIPv4NativeRoutingCIDR(); nativeCIDR != nil {
			found := false
			for _, vpcCIDR := range allCIDRs {
				logFields := logrus.Fields{
					"vpc-cidr":                   vpcCIDR.String(),
					option.IPv4NativeRoutingCIDR: nativeCIDR.String(),
				}

				ranges4, _ := ip.CoalesceCIDRs([]*net.IPNet{nativeCIDR.IPNet, vpcCIDR.IPNet})
				if len(ranges4) != 1 {
					log.WithFields(logFields).Info("Native routing CIDR does not contain VPC CIDR, trying next")
				} else {
					found = true
					log.WithFields(logFields).Info("Native routing CIDR contains VPC CIDR, ignoring autodetected VPC CIDRs.")
					break
				}
			}
			if !found {
				log.Fatal("None of the VPC CIDRs contains the specified native routing CIDR")
			}
		} else {
			log.WithFields(logrus.Fields{
				"vpc-cidr": primaryCIDR.String(),
			}).Info("Using autodetected primary VPC CIDR.")
			n.conf.SetIPv4NativeRoutingCIDR(primaryCIDR)
		}
		return true
	} else {
		log.Info("Could not determine VPC CIDRs")
		return false
	}
}

// hasMinimumIPsInPool returns true if the required number of IPs is available
// in the allocation pool. It also returns the number of IPs required and
// available.
func (n *nodeStore) hasMinimumIPsInPool() (minimumReached bool, required, numAvailable int) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.ownNode == nil {
		return
	}

	switch {
	case n.ownNode.Spec.IPAM.MinAllocate >= 0:
		required = n.ownNode.Spec.IPAM.MinAllocate
	case n.ownNode.Spec.IPAM.PreAllocate != 0:
		required = n.ownNode.Spec.IPAM.PreAllocate
	case n.conf.HealthCheckingEnabled():
		required = 2
	default:
		required = 1
	}

	if required == 0 {
		minimumReached = true
		return
	}

	if n.ownNode.Spec.IPAM.Pool != nil {
		for ip := range n.ownNode.Spec.IPAM.Pool {
			if !n.isIPInReleaseHandshake(ip) {
				numAvailable++
			}
		}
		if len(n.ownNode.Spec.IPAM.Pool) >= required {
			minimumReached = true
		}

		if n.conf.IPAMMode() == ipamOption.IPAMENI || n.conf.IPAMMode() == ipamOption.IPAMAzure || n.conf.IPAMMode() == ipamOption.IPAMAlibabaCloud || n.conf.IPAMMode() == ipamOption.IPAMOpenStack {
			if !n.autoDetectIPv4NativeRoutingCIDR() {
				minimumReached = false
			}
		}
	}

	if n.ownNode.Spec.IPAM.CrdPools != nil {
		if n.conf.IPAMMode() == ipamOption.IPAMOpenStack {

			if len(n.ownNode.Spec.IPAM.CrdPools) > 0 {
				defaultPool, exist := n.ownNode.Spec.IPAM.CrdPools[string(PoolDefault)]
				if !exist || len(defaultPool) < required {
					minimumReached = false
				} else {
					minimumReached = true
				}
				if exist {
					for ip := range defaultPool {
						if !n.isIPInReleaseHandshake(ip) {
							numAvailable++
						}
					}
				}
			}

			if !n.autoDetectIPv4NativeRoutingCIDR() {
				minimumReached = false
			}
		}
	}

	return
}

// deleteLocalNodeResource is called when the CiliumNode resource representing
// the local node has been deleted.
func (n *nodeStore) deleteLocalNodeResource() {
	n.mutex.Lock()
	n.ownNode = nil
	n.mutex.Unlock()
}

// updateLocalNodeResource is called when the CiliumNode resource representing
// the local node has been added or updated. It updates the available IPs based
// on the custom resource passed into the function.
func (n *nodeStore) updateLocalNodeResource(node *ciliumv2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.conf.IPAMMode() == ipamOption.IPAMENI {
		if err := configureENIDevices(n.ownNode, node, n.mtuConfig); err != nil {
			log.WithError(err).Errorf("Failed to update routes and rules for ENIs")
		}
	}

	if n.conf.IPAMMode() == ipamOption.IPAMOpenStack {
		if err := configureOpenStackENIs(n.ownNode, node, n.mtuConfig); err != nil {
			log.WithError(err).Errorf("Failed to configure openstack ENIs")
		}
	}

	n.ownNode = node
	n.allocationPoolSize[IPv4] = 0
	n.allocationPoolSize[IPv6] = 0
	if node.Spec.IPAM.Pool != nil {
		for ipString := range node.Spec.IPAM.Pool {
			if ip := net.ParseIP(ipString); ip != nil {
				if ip.To4() != nil {
					n.allocationPoolSize[IPv4]++
				} else {
					n.allocationPoolSize[IPv6]++
				}
			}
		}
	}

	availableCount := 0

	m := make(map[string]string)
	for p := range node.Spec.IPAM.CrdPools {
		for ip := range node.Spec.IPAM.CrdPools[p] {
			m[ip] = p
			if p != "default" {
				availableCount++
			}
		}
	}
	n.ipsToPool = m

	releaseUpstreamSyncNeeded := false
	// ACK or NACK IPs marked for release by the operator
	for ip, status := range n.ownNode.Status.IPAM.ReleaseIPs {
		if n.ownNode.Spec.IPAM.CrdPools == nil {
			continue
		}

		// ignore default pool
		if n.ipsToPool[ip] != "default" {
			if status == ipamOption.IPAMReleased ||
				status == ipamOption.IPAMMarkForRelease ||
				status == ipamOption.IPAMReadyForRelease {
				availableCount--
			}
		}

		// Ignore states that agent previously responded to.
		if status == ipamOption.IPAMReadyForRelease || status == ipamOption.IPAMDoNotRelease {
			continue
		}
		if p, ok := n.ipsToPool[ip]; ok {

			// Ignore all other states, transition to do-not-release and ready-for-release are allowed only from
			// marked-for-release
			if status != ipamOption.IPAMMarkForRelease {
				continue
			}
			// Retrieve the appropriate allocator
			var allocator *crdAllocator
			var ipFamily Family
			if ipAddr := net.ParseIP(ip); ipAddr != nil {
				ipFamily = DeriveFamily(ipAddr)
			}
			if ipFamily == "" {
				continue
			}
			for _, a := range n.allocators {
				if a.family == ipFamily {
					allocator = a
				}
			}
			if allocator == nil {
				continue
			}

			// Some functions like crdAllocator.Allocate() acquire lock on allocator first and then on nodeStore.
			// So release nodestore lock before acquiring allocator lock to avoid potential deadlocks from inconsistent
			// lock ordering.
			n.mutex.Unlock()
			allocator.mutex.Lock()
			if _, ok = allocator.poolAllocated[p]; ok {
				_, ok = allocator.poolAllocated[p][ip]
			}
			allocator.mutex.Unlock()
			n.mutex.Lock()
			if ok {
				// IP still in use, update the operator to stop releasing the IP.
				n.ownNode.Status.IPAM.ReleaseIPs[ip] = ipamOption.IPAMDoNotRelease
			} else {
				n.ownNode.Status.IPAM.ReleaseIPs[ip] = ipamOption.IPAMReadyForRelease
			}
			releaseUpstreamSyncNeeded = true
		} else {
			if status == ipamOption.IPAMReleased {
				// Remove entry from release-ips only when it is removed from .spec.ipam.pool as well
				delete(n.ownNode.Status.IPAM.ReleaseIPs, ip)
				releaseUpstreamSyncNeeded = true

				// Remove the unreachable route for this IP
				if n.conf.UnreachableRoutesEnabled() {
					parsedIP := net.ParseIP(ip)
					if parsedIP == nil {
						// Unable to parse IP, no point in trying to remove the route
						log.Warningf("Unable to parse IP %s", ip)
						continue
					}

					err := netlink.RouteDel(&netlink.Route{
						Dst:   &net.IPNet{IP: parsedIP, Mask: net.CIDRMask(32, 32)},
						Table: unix.RT_TABLE_MAIN,
						Type:  unix.RTN_UNREACHABLE,
					})
					if err != nil && !errors.Is(err, unix.ESRCH) {
						// We ignore ESRCH, as it means the entry was already deleted
						log.WithError(err).Warningf("Unable to delete unreachable route for IP %s", ip)
						continue
					}
				}
			} else if status == ipamOption.IPAMMarkForRelease {
				// NACK the IP, if this node doesn't own the IP
				n.ownNode.Status.IPAM.ReleaseIPs[ip] = ipamOption.IPAMDoNotRelease
				releaseUpstreamSyncNeeded = true
			}
			continue
		}
	}
	n.csipMgr.UpdateLocalCiliumNode(node.DeepCopy())

	if availableCount != n.devicePluginResource.Count {
		n.devicePluginResource.Count = availableCount
		if n.devicePluginServerInitialized {
			n.devicePluginResource.UpdateSignal <- struct{}{}
		}
		log.Infof("Updated eni-ip count: %d", n.devicePluginResource.Count)
	}

	if releaseUpstreamSyncNeeded {
		n.refreshTrigger.TriggerWithReason("excess IP release")
	}
}

// setOwnNodeWithoutPoolUpdate overwrites the local node copy (e.g. to update
// its resourceVersion) without updating the available IP pool.
func (n *nodeStore) setOwnNodeWithoutPoolUpdate(node *ciliumv2.CiliumNode) {
	n.mutex.Lock()
	n.ownNode = node
	n.mutex.Unlock()
}

// refreshNodeTrigger is called to refresh the custom resource after taking the
// configured rate limiting into account
//
// Note: The function signature includes the reasons argument in order to
// implement the trigger.TriggerFunc interface despite the argument being
// unused.
func (n *nodeStore) refreshNodeTrigger(reasons []string) {
	if err := n.refreshNode(); err != nil {
		log.WithError(err).Warning("Unable to update CiliumNode custom resource")
		n.refreshTrigger.TriggerWithReason("retry after error")
	}
}

// refreshNode updates the custom resource in the apiserver based on the latest
// information in the local node store
func (n *nodeStore) refreshNode() error {
	n.mutex.RLock()
	if n.ownNode == nil {
		n.mutex.RUnlock()
		return nil
	}

	node := n.ownNode.DeepCopy()
	staleCopyOfAllocators := make([]*crdAllocator, len(n.allocators))
	copy(staleCopyOfAllocators, n.allocators)
	n.mutex.RUnlock()

	node.Status.IPAM.PoolUsed = map[string]ipamTypes.AllocationMap{}

	for _, a := range staleCopyOfAllocators {
		a.mutex.RLock()
		for _, allocationMap := range a.poolAllocated {
			for ip, ipInfo := range allocationMap {
				if node.Status.IPAM.PoolUsed[ipInfo.Pool] == nil {
					node.Status.IPAM.PoolUsed[ipInfo.Pool] = map[string]ipamTypes.AllocationIP{}
				}
				node.Status.IPAM.PoolUsed[ipInfo.Pool][ip] = ipInfo
			}
		}
		a.mutex.RUnlock()
	}

	var err error
	_, err = n.clientset.CiliumV2().CiliumNodes().UpdateStatus(context.TODO(), node, metav1.UpdateOptions{})

	return err
}

// addAllocator adds a new CRD allocator to the node store
func (n *nodeStore) addAllocator(allocator *crdAllocator) {
	n.mutex.Lock()
	n.allocators = append(n.allocators, allocator)
	n.mutex.Unlock()
}

func (n *nodeStore) acquireResourceCount() int {
	return n.devicePluginResource.Count
}

// allocate checks if a particular IP can be allocated or return an error
func (n *nodeStore) allocate(ip net.IP, pool Pool, owner string) (*ipamTypes.AllocationIP, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.ownNode == nil {
		return nil, fmt.Errorf("CiliumNode for own node is not available")
	}

	if n.ownNode.Spec.IPAM.CrdPools[pool.String()] == nil {
		return nil, fmt.Errorf("No IPs available")
	}

	if n.isIPInReleaseHandshake(ip.String()) {
		return nil, fmt.Errorf("IP not available, marked or ready for release")
	}

	csip, err := n.csipMgr.GetStaticIPForPod(owner)
	if err != nil {
		return nil, fmt.Errorf("get csip crd failed, error is %s", err)
	}

	ipInfo := ipamTypes.AllocationIP{
		Pool: pool.String(),
	}
	var exist bool

	if csip != nil && csip.Status.IPStatus == v2alpha1.Assigned {
		if csip.Spec.ENIId != "" {
			ipInfo.Resource = csip.Spec.ENIId
		} else {
			return nil, NewIPNotAvailableInPoolError(ip)
		}
	} else {
		ipInfo, exist = n.ownNode.Spec.IPAM.CrdPools[pool.String()][ip.String()]
		if !exist {
			return nil, NewIPNotAvailableInPoolError(ip)
		}
		ipInfo.Pool = pool.String()
		if csip != nil && csip.Spec.ENIId != ipInfo.Resource {
			return nil, fmt.Errorf("IP not available, expected value is %s, but get is %s", csip.Spec.ENIId, ipInfo.Resource)
		}
	}

	return &ipInfo, nil
}

// isIPInReleaseHandshake validates if a given IP is currently in the process of being released
func (n *nodeStore) isIPInReleaseHandshake(ip string) bool {
	if n.ownNode.Status.IPAM.ReleaseIPs == nil {
		return false
	}
	if status, ok := n.ownNode.Status.IPAM.ReleaseIPs[ip]; ok {
		if status == ipamOption.IPAMMarkForRelease || status == ipamOption.IPAMReadyForRelease || status == ipamOption.IPAMReleased {
			return true
		}
	}
	return false
}

// allocateNext allocates the next available IP or returns an error
func (n *nodeStore) allocateNext(poolAllocated map[string]ipamTypes.AllocationMap, family Family, owner string, pool Pool) (net.IP, *ipamTypes.AllocationIP, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.ownNode == nil {
		return nil, nil, fmt.Errorf("CiliumNode for own node is not available")
	}

	if pool == PoolNotSpecified {
		maxFreeCount := 0
		var targetPool string

		for s := range n.ownNode.Spec.IPAM.CrdPools {
			if s == "default" {
				continue
			}
			availableCount := len(n.ownNode.Spec.IPAM.CrdPools[s])
			usedCount := 0

			for p := range n.ownNode.Spec.IPAM.CrdPools[s] {
				if n.isIPInReleaseHandshake(p) {
					availableCount--
				}
			}

			if used, ok := n.ownNode.Status.IPAM.PoolUsed[s]; ok {
				usedCount = len(used)
			}
			if availableCount-usedCount > maxFreeCount {
				targetPool = s
				maxFreeCount = availableCount - usedCount
			}
		}
		if targetPool != "" {
			pool = Pool(targetPool)
		} else {
			return nil, nil, fmt.Errorf("no target pool available")
		}
	}

	var allocate ipamTypes.AllocationMap
	allocated := poolAllocated[pool.String()]

	if n.ownNode.Spec.IPAM.CrdPools != nil && n.ownNode.Spec.IPAM.CrdPools[pool.String()] != nil {
		allocate = n.ownNode.Spec.IPAM.CrdPools[pool.String()]
	} else {
		allocate = n.ownNode.Spec.IPAM.Pool
	}

	// Check if IP has a custom owner (only supported in manual CRD mode)
	if n.conf.IPAMMode() == ipamOption.IPAMCRD && len(owner) != 0 {
		for ip, ipInfo := range allocate {
			if ipInfo.Owner == owner {
				parsedIP := net.ParseIP(ip)
				if parsedIP == nil {
					log.WithFields(logrus.Fields{
						fieldName: n.ownNode.Name,
						"ip":      ip,
					}).Warning("Unable to parse IP in CiliumNode custom resource")
					return nil, nil, fmt.Errorf("invalid custom ip %s for %s. ", ip, owner)
				}
				if DeriveFamily(parsedIP) != family {
					continue
				}
				return parsedIP, &ipInfo, nil
			}
		}
	}

	// FIXME: This is currently using a brute-force method that can be
	// optimized
	for ip, ipInfo := range allocate {
		if _, ok := allocated[ip]; !ok {

			if n.isIPInReleaseHandshake(ip) {
				continue // IP not available
			}
			if ipInfo.Owner != "" {
				continue // IP is used by another
			}
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				log.WithFields(logrus.Fields{
					fieldName: n.ownNode.Name,
					"ip":      ip,
				}).Warning("Unable to parse IP in CiliumNode custom resource")
				continue
			}

			if n.csipMgr != nil {
				if ownerBy, isCsip := n.csipMgr.IsCSIPAddress(ip); isCsip {
					if ownerBy != owner {
						continue
					}
				}
			}

			if DeriveFamily(parsedIP) != family {
				continue
			}
			ipInfo.Pool = pool.String()

			return parsedIP, &ipInfo, nil
		}
	}

	return nil, nil, fmt.Errorf("No more IPs available")
}

// totalPoolSize returns the total size of the allocation pool
func (n *nodeStore) totalPoolSize(family Family) int {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if num, ok := n.allocationPoolSize[family]; ok {
		return num
	}
	return 0
}

// crdAllocator implements the CRD-backed IP allocator
type crdAllocator struct {
	// store is the node store backing the custom resource
	store *nodeStore

	// mutex protects access to the allocated map
	mutex lock.RWMutex

	// allocated is a map of all allocated IPs indexed by the allocated IP
	// represented as string
	allocated ipamTypes.AllocationMap

	poolAllocated map[string]ipamTypes.AllocationMap

	// family is the address family this allocator is allocator for
	family Family

	conf Configuration
}

// newCRDAllocator creates a new CRD-backed IP allocator
func newCRDAllocator(family Family, c Configuration, owner Owner, clientset client.Clientset, k8sEventReg K8sEventRegister, mtuConfig MtuConfiguration, csipMgr *staticip.Manager, metadata *ipamMetadata.Manager, projectLabelGetter utils.NodeLabelForProjectConfiguration) Allocator {
	initNodeStore.Do(func() {
		sharedNodeStore = newNodeStore(nodeTypes.GetName(), c, owner, clientset, k8sEventReg, mtuConfig, csipMgr, metadata, projectLabelGetter)
	})

	allocator := &crdAllocator{
		allocated:     ipamTypes.AllocationMap{},
		family:        family,
		store:         sharedNodeStore,
		conf:          c,
		poolAllocated: map[string]ipamTypes.AllocationMap{},
	}

	sharedNodeStore.addAllocator(allocator)

	return allocator
}

// deriveGatewayIP accept the CIDR and the index of the IP in this CIDR.
func deriveGatewayIP(cidr string, index int) string {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.WithError(err).Warningf("Unable to parse subnet CIDR %s", cidr)
		return ""
	}
	gw := ip.GetIPAtIndex(*ipNet, int64(index))
	if gw == nil {
		return ""
	}
	return gw.String()
}

func (a *crdAllocator) buildAllocationResult(ip net.IP, ipInfo *ipamTypes.AllocationIP) (result *AllocationResult, err error) {
	result = &AllocationResult{IP: ip}

	a.store.mutex.RLock()
	defer a.store.mutex.RUnlock()

	if a.store.ownNode == nil {
		return
	}

	switch a.conf.IPAMMode() {

	// In ENI mode, the Resource points to the ENI so we can derive the
	// master interface and all CIDRs of the VPC
	case ipamOption.IPAMENI:
		for _, eni := range a.store.ownNode.Status.ENI.ENIs {
			if eni.ID == ipInfo.Resource {
				result.PrimaryMAC = eni.MAC
				result.CIDRs = []string{eni.VPC.PrimaryCIDR}
				result.CIDRs = append(result.CIDRs, eni.VPC.CIDRs...)
				// Add manually configured Native Routing CIDR
				if a.conf.GetIPv4NativeRoutingCIDR() != nil {
					result.CIDRs = append(result.CIDRs, a.conf.GetIPv4NativeRoutingCIDR().String())
				}
				if eni.Subnet.CIDR != "" {
					// The gateway for a subnet and VPC is always x.x.x.1
					// Ref: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html
					result.GatewayIP = deriveGatewayIP(eni.Subnet.CIDR, 1)
				}
				result.InterfaceNumber = strconv.Itoa(eni.Number)

				return
			}
		}
		return nil, fmt.Errorf("unable to find ENI %s", ipInfo.Resource)

	// In Azure mode, the Resource points to the azure interface so we can
	// derive the master interface
	case ipamOption.IPAMAzure:
		for _, iface := range a.store.ownNode.Status.Azure.Interfaces {
			if iface.ID == ipInfo.Resource {
				result.PrimaryMAC = iface.MAC
				result.GatewayIP = iface.Gateway
				result.CIDRs = append(result.CIDRs, iface.CIDR)
				// For now, we can hardcode the interface number to a valid
				// integer because it will not be used in the allocation result
				// anyway. To elaborate, Azure IPAM mode automatically sets
				// option.Config.EgressMultiHomeIPRuleCompat to true, meaning
				// that the CNI will not use the interface number when creating
				// the pod rules and routes. We are hardcoding simply to bypass
				// the parsing errors when InterfaceNumber is empty. See
				// https://github.com/cilium/cilium/issues/15496.
				//
				// TODO: Once https://github.com/cilium/cilium/issues/14705 is
				// resolved, then we don't need to hardcode this anymore.
				result.InterfaceNumber = "0"
				return
			}
		}
		return nil, fmt.Errorf("unable to find ENI %s", ipInfo.Resource)

	// In AlibabaCloud mode, the Resource points to the ENI so we can derive the
	// master interface and all CIDRs of the VPC
	case ipamOption.IPAMAlibabaCloud:
		for _, eni := range a.store.ownNode.Status.AlibabaCloud.ENIs {
			if eni.NetworkInterfaceID != ipInfo.Resource {
				continue
			}
			result.PrimaryMAC = eni.MACAddress
			result.CIDRs = []string{eni.VSwitch.CIDRBlock}

			// Ref: https://www.alibabacloud.com/help/doc-detail/65398.html
			result.GatewayIP = deriveGatewayIP(eni.VSwitch.CIDRBlock, -3)
			result.InterfaceNumber = strconv.Itoa(alibabaCloud.GetENIIndexFromTags(eni.Tags))
			return
		}
		return nil, fmt.Errorf("unable to find ENI %s", ipInfo.Resource)

	case ipamOption.IPAMOpenStack:
		for _, eni := range a.store.ownNode.Status.OpenStack.ENIs {
			if eni.ID == ipInfo.Resource {
				result.PrimaryMAC = eni.MAC
				result.CIDRs = []string{eni.Subnet.CIDR}
				result.CIDRs = append(result.CIDRs, eni.Subnet.CIDR)
				// Add manually configured Native Routing CIDR
				if a.conf.GetIPv4NativeRoutingCIDR() != nil {
					result.CIDRs = append(result.CIDRs, a.conf.GetIPv4NativeRoutingCIDR().String())
				}
				if eni.Subnet.GatewayIP != "" {
					result.GatewayIP = eni.Subnet.GatewayIP
				} else {
					result.GatewayIP = deriveGatewayIP(eni.Subnet.CIDR, option.Config.OpenStackGateWayIndex)
				}
				result.InterfaceNumber = strconv.Itoa(openStack.GetENIIndexFromTags(eni.Tags))
				result.IPPoolName = Pool(ipInfo.Pool)
				return
			}
		}
		return nil, fmt.Errorf("unable to find ENI %s", ipInfo.Resource)

	}

	return
}

// Allocate will attempt to find the specified IP in the custom resource and
// allocate it if it is available. If the IP is unavailable or already
// allocated, an error is returned. The custom resource will be updated to
// reflect the newly allocated IP.
func (a *crdAllocator) Allocate(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.poolAllocated[pool.String()] == nil {
		a.poolAllocated[pool.String()] = map[string]ipamTypes.AllocationIP{}
	}

	if am, ok := a.poolAllocated[pool.String()][ip.String()]; ok {
		if am.Owner != owner {
			if am.Owner+" [restored]" != owner {
				return nil, fmt.Errorf("IP already in use")
			}
		}
	}

	ipInfo, err := a.store.allocate(ip, pool, owner)
	if err != nil {
		return nil, err
	}

	result, err := a.buildAllocationResult(ip, ipInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to associate IP %s inside CiliumNode: %w", ip, err)
	}

	result.Resource = ipInfo.Resource

	a.markAllocated(ip, owner, *ipInfo)
	// Update custom resource to reflect the newly allocated IP.
	a.store.refreshTrigger.TriggerWithReason(fmt.Sprintf("allocation of IP %s", ip.String()))

	return result, nil
}

// AllocateWithoutSyncUpstream will attempt to find the specified IP in the
// custom resource and allocate it if it is available. If the IP is
// unavailable or already allocated, an error is returned. The custom resource
// will not be updated.
func (a *crdAllocator) AllocateWithoutSyncUpstream(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if am, ok := a.poolAllocated[pool.String()][ip.String()]; ok {
		if am.Owner != owner {
			if am.Owner+" [restored]" != owner {
				return nil, fmt.Errorf("IP already in use")
			}
		}
	}

	ipInfo, err := a.store.allocate(ip, pool, owner)
	if err != nil {
		return nil, err
	}

	result, err := a.buildAllocationResult(ip, ipInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to associate IP %s inside CiliumNode: %w", ip, err)
	}

	a.markAllocated(ip, owner, *ipInfo)

	return result, nil
}

// Release will release the specified IP or return an error if the IP has not
// been allocated before. The custom resource will be updated to reflect the
// released IP.
func (a *crdAllocator) Release(ip net.IP, pool Pool) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if _, ok := a.poolAllocated[pool.String()][ip.String()]; !ok {
		return fmt.Errorf("IP %s is not allocated", ip.String())
	}

	delete(a.poolAllocated[pool.String()], ip.String())
	// Update custom resource to reflect the newly released IP.
	a.store.refreshTrigger.TriggerWithReason(fmt.Sprintf("release of IP %s", ip.String()))

	return nil
}

// markAllocated marks a particular IP as allocated
func (a *crdAllocator) markAllocated(ip net.IP, owner string, ipInfo ipamTypes.AllocationIP) {
	ipInfo.Owner = owner
	if a.poolAllocated[ipInfo.Pool] == nil {
		a.poolAllocated[ipInfo.Pool] = map[string]ipamTypes.AllocationIP{}
	}
	a.poolAllocated[ipInfo.Pool][ip.String()] = ipInfo
}

// AllocateNext allocates the next available IP as offered by the custom
// resource or return an error if no IP is available. The custom resource will
// be updated to reflect the newly allocated IP.
func (a *crdAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	ip, ipInfo, err := a.store.allocateNext(a.poolAllocated, a.family, owner, pool)
	if err != nil {
		return nil, err
	}

	result, err := a.buildAllocationResult(ip, ipInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to associate IP %s inside CiliumNode: %w", ip, err)
	}

	a.markAllocated(ip, owner, *ipInfo)
	// Update custom resource to reflect the newly allocated IP.
	a.store.refreshTrigger.TriggerWithReason(fmt.Sprintf("allocation of IP %s", ip.String()))

	return result, nil
}

// AllocateNextWithoutSyncUpstream allocates the next available IP as offered
// by the custom resource or return an error if no IP is available. The custom
// resource will not be updated.
func (a *crdAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	ip, ipInfo, err := a.store.allocateNext(a.poolAllocated, a.family, owner, pool)
	if err != nil {
		return nil, err
	}

	result, err := a.buildAllocationResult(ip, ipInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to associate IP %s inside CiliumNode: %w", ip, err)
	}

	a.markAllocated(ip, owner, *ipInfo)

	return result, nil
}

// Dump provides a status report and lists all allocated IP addresses
func (a *crdAllocator) Dump() (map[string]string, string) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	allocs := map[string]string{}
	for _, allocationMap := range a.poolAllocated {
		for ip := range allocationMap {
			allocs[ip] = ""
		}
	}

	status := fmt.Sprintf("%d/%d allocated", len(allocs), a.store.totalPoolSize(a.family))
	return allocs, status
}

// RestoreFinished marks the status of restoration as done
func (a *crdAllocator) RestoreFinished() {
	a.store.restoreCloseOnce.Do(func() {
		close(a.store.restoreFinished)
	})
}

// NewIPNotAvailableInPoolError returns an error resprenting the given IP not
// being available in the IPAM pool.
func NewIPNotAvailableInPoolError(ip net.IP) error {
	return &ErrIPNotAvailableInPool{ip: ip}
}

// ErrIPNotAvailableInPool represents an error when an IP is not available in
// the pool.
type ErrIPNotAvailableInPool struct {
	ip net.IP
}

func (e *ErrIPNotAvailableInPool) Error() string {
	return fmt.Sprintf("IP %s is not available", e.ip.String())
}

// Is provides this error type with the logic for use with errors.Is.
func (e *ErrIPNotAvailableInPool) Is(target error) bool {
	if e == nil || target == nil {
		return false
	}
	t, ok := target.(*ErrIPNotAvailableInPool)
	if !ok {
		return ok
	}
	if t == nil {
		return false
	}
	return t.ip.Equal(e.ip)
}

func (n *nodeStore) getNonDevicePluginPodCount() (int, error) {
	count := 0
	values, err := n.metadata.GetLocalPods()
	if err != nil {
		pods, err := n.clientset.Slim().CoreV1().Pods(v12.NamespaceAll).List(context.TODO(), metav1.ListOptions{
			FieldSelector:   fields.OneTermEqualSelector("spec.nodeName", nodeTypes.GetName()).String(),
			ResourceVersion: "0"})

		if err != nil {
			return 0, fmt.Errorf("unable to get local pods: %s", err)
		}

		for i := range pods.Items {
			values = append(values, &pods.Items[i])
		}
	}

	defaultPool, err := n.clientset.CiliumV2alpha1().CiliumPodIPPools().Get(context.TODO(), "default", metav1.GetOptions{ResourceVersion: "0"})
	if err != nil {
		return 0, fmt.Errorf("unable to get default ciliumPodNetwork: %s", err)
	}

	_, ipNet, err := net.ParseCIDR(defaultPool.Spec.CIDR)
	if err != nil {
		return 0, fmt.Errorf("unable to get default pool's cidr: %s", err)
	}

	for i := range values {
		if !values[i].Spec.HostNetwork {
			if _, exist := values[i].Spec.Containers[0].Resources.Requests[v12.ResourceName(deviceplugin.ENIIPResourcePrefix+n.projectName)]; !exist &&
				len(values[i].Status.PodIPs) > 0 &&
				// 非default pool 且没有注入device-plugin资源
				!ipNet.Contains(net.ParseIP(values[i].Status.PodIP)) {
				count++
			}
		}
	}
	return count, nil
}
