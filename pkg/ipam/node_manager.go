// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2017 Lyft, Inc.

package ipam

import (
	"context"
	"fmt"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/openstack/eni/limits"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/controller"
	ipamStats "github.com/cilium/cilium/pkg/ipam/stats"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/trigger"
)

// CiliumNodeGetterUpdater defines the interface used to interact with the k8s
// apiserver to retrieve and update the CiliumNode custom resource
type CiliumNodeGetterUpdater interface {
	Create(node *v2.CiliumNode) (*v2.CiliumNode, error)
	Update(origResource, newResource *v2.CiliumNode) (*v2.CiliumNode, error)
	UpdateStatus(origResource, newResource *v2.CiliumNode) (*v2.CiliumNode, error)
	Get(name string) (*v2.CiliumNode, error)
}

// NodeOperations is the interface an IPAM implementation must provide in order
// to provide IP allocation for a node. The structure implementing this API
// *must* be aware of the node connected to this implementation. This is
// achieved by considering the node context provided in
// AllocationImplementation.CreateNode() function and returning a
// NodeOperations implementation which performs operations in the context of
// that node.
type NodeOperations interface {
	// UpdateNode is called when an update to the CiliumNode is received.
	UpdatedNode(obj *v2.CiliumNode)

	// PopulateStatusFields is called to give the implementation a chance
	// to populate any implementation specific fields in CiliumNode.Status.
	PopulateStatusFields(resource *v2.CiliumNode)

	// CreateInterface is called to create a new interface. This is only
	// done if PrepareIPAllocation indicates that no more IPs are available
	// (AllocationAction.AvailableForAllocation == 0) for allocation but
	// interfaces are available for creation
	// (AllocationAction.EmptyInterfaceSlots > 0). This function must
	// create the interface *and* allocate up to
	// AllocationAction.MaxIPsToAllocate.
	CreateInterface(ctx context.Context, allocation *AllocationAction, scopedLog *logrus.Entry, pool Pool) (int, string, error)

	// ResyncInterfacesAndIPs is called to synchronize the latest list of
	// interfaces and IPs associated with the node. This function is called
	// sparingly as this information is kept in sync based on the success
	// of the functions AllocateIPs(), ReleaseIPs() and CreateInterface().
	// It returns all available ip in node and remaining available interfaces
	// that can either be allocated or have not yet exhausted the instance specific quota of addresses
	// and error occurred during execution.
	ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry) (ipamTypes.AllocationMap, ipamStats.InterfaceStats, error)

	ResyncInterfacesAndIPsByPool(ctx context.Context, scopedLog *logrus.Entry) (poolAvailable map[Pool]ipamTypes.AllocationMap, stats ipamStats.InterfaceStats, err error)

	// PrepareIPAllocation is called to calculate the number of IPs that
	// can be allocated on the node and whether a new network interface
	// must be attached to the node.
	PrepareIPAllocation(scopedLog *logrus.Entry, pool Pool) (*AllocationAction, error)

	// AllocateIPs is called after invoking PrepareIPAllocation and needs
	// to perform the actual allocation.
	AllocateIPs(ctx context.Context, allocation *AllocationAction, pool Pool) error

	// PrepareIPRelease is called to calculate whether any IP excess needs
	// to be resolved. It behaves identical to PrepareIPAllocation but
	// indicates a need to release IPs.
	PrepareIPRelease(excessIPs int, scopedLog *logrus.Entry, pool Pool) *ReleaseAction

	// ReleaseIPs is called after invoking PrepareIPRelease and needs to
	// perform the release of IPs.
	ReleaseIPs(ctx context.Context, release *ReleaseAction) error

	// GetMaximumAllocatableIPv4 returns the maximum amount of IPv4 addresses
	// that can be allocated to the instance
	GetMaximumAllocatableIPv4() int

	// GetMinimumAllocatableIPv4 returns the minimum amount of IPv4 addresses that
	// must be allocated to the instance.
	GetMinimumAllocatableIPv4() int

	// IsPrefixDelegated helps identify if a node supports prefix delegation
	IsPrefixDelegated() bool

	// GetPoolUsedIPWithPrefixes returns the total number of used IPs by pool including all IPs in a prefix if at-least one of
	// the prefix IPs is in use.
	GetPoolUsedIPWithPrefixes(pool string) int

	// GetUsedIPWithPrefixes returns the total number of used IPs including all IPs in a prefix if at-least one of
	// the prefix IPs is in use.
	GetUsedIPWithPrefixes() int

	// AllocateStaticIP is called after invoking PrepareIPAllocation and needs
	// to allocate the static ip on specific eni.
	AllocateStaticIP(ctx context.Context, address string, interfaceId string, pool Pool) error

	// UnbindStaticIP is called to unbind the static ip from eni but retain the neutron port
	UnbindStaticIP(ctx context.Context, address string, poolID string) error

	// ReleaseStaticIP is called to delete the neutron port
	ReleaseStaticIP(address string, pool string) error
}

// AllocationImplementation is the interface an implementation must provide.
// Other than NodeOperations, this implementation is not related to a node
// specifically.
type AllocationImplementation interface {
	// CreateNode is called when the IPAM layer has learned about a new
	// node which requires IPAM services. This function must return a
	// NodeOperations implementation which will render IPAM services to the
	// node context provided.
	CreateNode(obj *v2.CiliumNode, node *Node) NodeOperations

	// GetPoolQuota is called to retrieve the remaining IP addresses in all
	// IP pools known to the IPAM implementation.
	GetPoolQuota() ipamTypes.PoolQuotaMap

	// Resync is called periodically to give the IPAM implementation a
	// chance to resync its own state with external APIs or systems. It is
	// also called when the IPAM layer detects that state got out of sync.
	Resync(ctx context.Context) time.Time

	InstanceSync(ctx context.Context, instanceID string) time.Time

	// HasInstance returns whether the instance is in instances
	HasInstance(instanceID string) bool

	// DeleteInstance deletes the instance from instances
	DeleteInstance(instanceID string)

	ExcludeIP(ip string)

	IncludeIP(ip string)
}

// MetricsAPI represents the metrics being maintained by a NodeManager
type MetricsAPI interface {
	MetricsNodeAPI

	AllocationAttempt(typ, status, subnetID string, observe float64)
	ReleaseAttempt(typ, status, subnetID string, observe float64)
	IncInterfaceAllocation(subnetID string)
	AddIPAllocation(subnetID string, allocated int64)
	AddIPRelease(subnetID string, released int64)
	SetAllocatedIPs(typ string, allocated int)
	SetAvailableInterfaces(available int)
	SetInterfaceCandidates(interfaceCandidates int)
	SetEmptyInterfaceSlots(emptyInterfaceSlots int)
	SetAvailableIPsPerSubnet(subnetID string, availabilityZone string, available int)
	SetNodes(category string, nodes int)
	IncResyncCount()
	PoolMaintainerTrigger() trigger.MetricsObserver
	K8sSyncTrigger() trigger.MetricsObserver
	ResyncTrigger() trigger.MetricsObserver
}

type MetricsNodeAPI interface {
	SetIPAvailable(node string, cap int)
	SetIPUsed(node string, used int)
	SetIPNeeded(node string, needed int)
}

// nodeMap is a mapping of node names to ENI nodes
type nodeMap map[string]*Node

type poolMap map[string]*cilium_v2.CiliumPodIPPool

// NodeManager manages all nodes with ENIs
type NodeManager struct {
	mutex              lock.RWMutex
	nodes              nodeMap
	instancesAPI       AllocationImplementation
	k8sAPI             CiliumNodeGetterUpdater
	metricsAPI         MetricsAPI
	parallelWorkers    int64
	releaseExcessIPs   bool
	stableInstancesAPI bool
	prefixDelegation   bool

	pools poolMap
}

func (n *NodeManager) ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration {
	n.mutex.RLock()
	numNodes := len(n.nodes)
	n.mutex.RUnlock()

	return backoff.ClusterSizeDependantInterval(baseInterval, numNodes)
}

// NewNodeManager returns a new NodeManager
func NewNodeManager(instancesAPI AllocationImplementation, k8sAPI CiliumNodeGetterUpdater, metrics MetricsAPI,
	parallelWorkers int64, releaseExcessIPs bool, prefixDelegation bool) (*NodeManager, error) {
	if parallelWorkers < 1 {
		parallelWorkers = 1
	}

	mngr := &NodeManager{
		nodes:            nodeMap{},
		instancesAPI:     instancesAPI,
		k8sAPI:           k8sAPI,
		metricsAPI:       metrics,
		parallelWorkers:  parallelWorkers,
		releaseExcessIPs: releaseExcessIPs,
		prefixDelegation: prefixDelegation,
		pools:            poolMap{},
	}

	// Assume readiness, the initial blocking resync in Start() will update
	// the readiness
	mngr.SetInstancesAPIReadiness(true)
	k8sManager.nodeManager = mngr

	return mngr, nil
}

func (n *NodeManager) instancesAPIResync(ctx context.Context) (time.Time, bool) {
	syncTime := n.instancesAPI.Resync(ctx)
	success := !syncTime.IsZero()
	n.SetInstancesAPIReadiness(success)
	return syncTime, success
}

// Start kicks of the NodeManager by performing the initial state
// synchronization and starting the background sync goroutine
func (n *NodeManager) Start(ctx context.Context) error {
	// Trigger the initial resync in a blocking manner
	if _, ok := n.instancesAPIResync(ctx); !ok {
		return fmt.Errorf("Initial synchronization with instances API failed")
	}

	// Start an interval based  background resync for safety, it will
	// synchronize the state regularly and resolve eventual deficit if the
	// event driven trigger fails, and also release excess IP addresses
	// if release-excess-ips is enabled
	go func() {
		mngr := controller.NewManager()
		mngr.UpdateController("ipam-node-interval-refresh",
			controller.ControllerParams{
				RunInterval: time.Minute,
				DoFunc: func(ctx context.Context) error {
					if syncTime, ok := n.instancesAPIResync(ctx); ok {
						for _, node := range n.nodes {
							err := n.SyncMultiPool(node)
							if err != nil {
								log.Errorf("node %s syncMultiPool failed, error is %s ", node.name, err)
							}
						}

						n.Resync(ctx, syncTime)

						return nil
					}
					return nil
				},
			})
	}()

	return nil
}

// SetInstancesAPIReadiness sets the readiness state of the instances API
func (n *NodeManager) SetInstancesAPIReadiness(ready bool) {
	n.mutex.Lock()
	n.stableInstancesAPI = ready
	n.mutex.Unlock()
}

// InstancesAPIIsReady returns true if the instances API is stable and ready
func (n *NodeManager) InstancesAPIIsReady() bool {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return n.stableInstancesAPI
}

// GetNames returns the list of all node names
func (n *NodeManager) GetNames() (allNodeNames []string) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	allNodeNames = make([]string, 0, len(n.nodes))

	for name := range n.nodes {
		allNodeNames = append(allNodeNames, name)
	}

	return
}

// Upsert is called whenever a CiliumNode resource has been updated in the
// Kubernetes apiserver. The CiliumNode will be created if it didn't exist before.
func (n *NodeManager) Upsert(resource *v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	node, ok := n.nodes[resource.Name]
	if !ok {
		node = &Node{
			name:                resource.Name,
			manager:             n,
			ipsMarkedForRelease: make(map[string]time.Time),
			ipReleaseStatus:     make(map[string]string),
			logLimiter:          logging.NewLimiter(10*time.Second, 3), // 1 log / 10 secs, burst of 3
			pools:               map[Pool]pool{},
			poolStats:           map[Pool]*Statistics{},
			poolAvailable:       map[Pool]ipamTypes.AllocationMap{},
		}

		ctx, cancel := context.WithCancel(context.Background())
		// InstanceAPI is stale and the instances API is stable then do resync instancesAPI to sync instances
		if !n.instancesAPI.HasInstance(resource.InstanceID()) && n.stableInstancesAPI {
			if syncTime := n.instancesAPI.Resync(ctx); syncTime.IsZero() {
				node.logger().Warning("Failed to resync the instances from the API after new node was found")
				n.stableInstancesAPI = false
			} else {
				n.stableInstancesAPI = true
			}
		}

		node.ops = n.instancesAPI.CreateNode(resource, node)

		backoff := &backoff.Exponential{
			Max:         5 * time.Minute,
			Jitter:      true,
			NodeManager: n,
			Name:        fmt.Sprintf("ipam-pool-maintainer-%s", resource.Name),
			ResetAfter:  10 * time.Minute,
		}
		poolMaintainer, err := trigger.NewTrigger(trigger.Parameters{
			Name:            fmt.Sprintf("ipam-pool-maintainer-%s", resource.Name),
			MinInterval:     10 * time.Millisecond,
			MetricsObserver: n.metricsAPI.PoolMaintainerTrigger(),
			TriggerFunc: func(reasons []string) {
				if err := node.MaintainIPPool(ctx); err != nil {
					node.logger().WithError(err).Warning("Unable to maintain ip pool of node")
					backoff.Wait(ctx)
				}
			},
			ShutdownFunc: cancel,
		})
		if err != nil {
			node.logger().WithError(err).Error("Unable to create pool-maintainer trigger")
			return
		}

		retry, err := trigger.NewTrigger(trigger.Parameters{
			Name:        fmt.Sprintf("ipam-pool-maintainer-%s-retry", resource.Name),
			MinInterval: time.Minute, // large minimal interval to not retry too often
			TriggerFunc: func(reasons []string) { poolMaintainer.Trigger() },
		})
		if err != nil {
			node.logger().WithError(err).Error("Unable to create pool-maintainer-retry trigger")
			return
		}
		node.retry = retry

		k8sSync, err := trigger.NewTrigger(trigger.Parameters{
			Name:            fmt.Sprintf("ipam-node-k8s-sync-%s", resource.Name),
			MinInterval:     10 * time.Millisecond,
			MetricsObserver: n.metricsAPI.K8sSyncTrigger(),
			TriggerFunc: func(reasons []string) {
				node.syncToAPIServer()
			},
		})
		if err != nil {
			poolMaintainer.Shutdown()
			node.logger().WithError(err).Error("Unable to create k8s-sync trigger")
			return
		}

		instanceSync, err := trigger.NewTrigger(trigger.Parameters{
			Name:            fmt.Sprintf("ipam-node-instance-sync-%s", resource.Name),
			MinInterval:     10 * time.Millisecond,
			MetricsObserver: n.metricsAPI.ResyncTrigger(),
			TriggerFunc: func(reasons []string) {
				if syncTime, ok := node.instanceAPISync(ctx, resource.InstanceID()); ok {
					node.manager.Resync(ctx, syncTime)
				}
			},
		})
		if err != nil {
			poolMaintainer.Shutdown()
			k8sSync.Shutdown()
			node.logger().WithError(err).Error("Unable to create instance-sync trigger")
			return
		}
		node.instanceSync = instanceSync

		node.poolMaintainer = poolMaintainer
		node.k8sSync = k8sSync
		n.nodes[node.name] = node
		log.WithField(fieldName, resource.Name).Info("Discovered new CiliumNode custom resource")
	}

	// Update the resource in the node while holding the lock, otherwise resyncs can be
	// triggered prior to the update being applied.
	node.UpdatedResource(resource)

}

// Delete is called after a CiliumNode resource has been deleted via the
// Kubernetes apiserver
func (n *NodeManager) Delete(resource *v2.CiliumNode) {
	n.mutex.Lock()

	if node, ok := n.nodes[resource.Name]; ok {
		if node.poolMaintainer != nil {
			node.poolMaintainer.Shutdown()
		}
		if node.k8sSync != nil {
			node.k8sSync.Shutdown()
		}
		if node.retry != nil {
			node.retry.Shutdown()
		}
		if node.instanceSync != nil {
			node.instanceSync.Shutdown()
		}

		n.instancesAPI.DeleteInstance(node.InstanceID())
	}

	// Delete the instance from instanceManager. This will cause Update() to
	// invoke instancesAPIResync if this instance rejoins the cluster.
	// This ensures that Node.recalculate() does not use stale data for
	// instances which rejoin the cluster after their EC2 configuration has changed.
	if resource.Spec.InstanceID != "" {
		n.instancesAPI.DeleteInstance(resource.Spec.InstanceID)
	}

	delete(n.nodes, resource.Name)
	n.mutex.Unlock()
}

// Get returns the node with the given name
func (n *NodeManager) Get(nodeName string) *Node {
	n.mutex.RLock()
	node := n.nodes[nodeName]
	n.mutex.RUnlock()
	return node
}

// GetNodesByIPWatermark returns all nodes that require addresses to be
// allocated or released, sorted by the number of addresses needed to be operated
// in descending order. Number of addresses to be released is negative value
// so that nodes with IP deficit are resolved first
func (n *NodeManager) GetNodesByIPWatermark() []*Node {
	n.mutex.RLock()
	list := make([]*Node, len(n.nodes))
	index := 0
	for _, node := range n.nodes {
		list[index] = node
		index++
	}
	n.mutex.RUnlock()

	sort.Slice(list, func(i, j int) bool {
		valuei := list[i].GetNeededAddresses()
		valuej := list[j].GetNeededAddresses()
		// Number of addresses to be released is negative value,
		// nodes with more excess addresses are released earlier
		if valuei < 0 && valuej < 0 {
			return valuei < valuej
		}
		return valuei > valuej
	})

	return list
}

type resyncStats struct {
	mutex               lock.Mutex
	totalUsed           int
	totalAvailable      int
	totalNeeded         int
	remainingInterfaces int
	interfaceCandidates int
	emptyInterfaceSlots int
	nodes               int
	nodesAtCapacity     int
	nodesInDeficit      int
	nodeCapacity        int
}

func (n *NodeManager) resyncNode(ctx context.Context, node *Node, stats *resyncStats, syncTime time.Time) {
	node.updateLastResync(syncTime)
	node.recalculate()
	allocationNeeded := node.allocationNeeded()
	releaseNeeded := node.releaseNeeded()
	if allocationNeeded || releaseNeeded {
		node.requirePoolMaintenance()
		node.poolMaintainer.Trigger()
	}

	nodeStats := node.Stats()

	stats.mutex.Lock()
	stats.totalUsed += nodeStats.UsedIPs
	// availableOnNode is the number of available IPs on the node at this
	// current moment. It does not take into account the number of IPs that
	// can be allocated in the future.
	availableOnNode := nodeStats.AvailableIPs - nodeStats.UsedIPs
	stats.totalAvailable += availableOnNode
	stats.totalNeeded += nodeStats.NeededIPs
	stats.remainingInterfaces += nodeStats.RemainingInterfaces
	stats.interfaceCandidates += nodeStats.InterfaceCandidates
	stats.emptyInterfaceSlots += nodeStats.EmptyInterfaceSlots
	stats.nodes++

	stats.nodeCapacity = nodeStats.Capacity

	// Set per Node metrics.
	n.metricsAPI.SetIPAvailable(node.name, stats.nodeCapacity)
	n.metricsAPI.SetIPUsed(node.name, nodeStats.UsedIPs)
	n.metricsAPI.SetIPNeeded(node.name, nodeStats.NeededIPs)

	if allocationNeeded {
		stats.nodesInDeficit++
	}

	if nodeStats.RemainingInterfaces == 0 && availableOnNode == 0 {
		stats.nodesAtCapacity++
	}

	stats.mutex.Unlock()

	node.k8sSync.Trigger()
}

// Resync will attend all nodes and resolves IP deficits. The order of
// attendance is defined by the number of IPs needed to reach the configured
// watermarks. Any updates to the node resource are synchronized to the
// Kubernetes apiserver.
func (n *NodeManager) Resync(ctx context.Context, syncTime time.Time) {
	n.metricsAPI.IncResyncCount()

	stats := resyncStats{}
	sem := semaphore.NewWeighted(n.parallelWorkers)

	for _, node := range n.GetNodesByIPWatermark() {
		log.Infof("!!!!!!!!!!!!! node details is %+v", node)
		err := sem.Acquire(ctx, 1)
		if err != nil {
			continue
		}
		go func(node *Node, stats *resyncStats) {
			n.resyncNode(ctx, node, stats, syncTime)
			sem.Release(1)
		}(node, &stats)
	}

	// Acquire the full semaphore, this requires all goroutines to
	// complete and thus blocks until all nodes are synced
	sem.Acquire(ctx, n.parallelWorkers)

	n.metricsAPI.SetAllocatedIPs("used", stats.totalUsed)
	n.metricsAPI.SetAllocatedIPs("available", stats.totalAvailable)
	n.metricsAPI.SetAllocatedIPs("needed", stats.totalNeeded)
	n.metricsAPI.SetAvailableInterfaces(stats.remainingInterfaces)
	n.metricsAPI.SetInterfaceCandidates(stats.interfaceCandidates)
	n.metricsAPI.SetEmptyInterfaceSlots(stats.emptyInterfaceSlots)
	n.metricsAPI.SetNodes("total", stats.nodes)
	n.metricsAPI.SetNodes("in-deficit", stats.nodesInDeficit)
	n.metricsAPI.SetNodes("at-capacity", stats.nodesAtCapacity)

	for poolID, quota := range n.instancesAPI.GetPoolQuota() {
		n.metricsAPI.SetAvailableIPsPerSubnet(string(poolID), quota.AvailabilityZone, quota.AvailableIPs)
	}
}

// SyncMultiPool labels the node with "openstack-ip-pool" when a ciliumNode upsert or a k8s node's pool annotation changed
func (n *NodeManager) SyncMultiPool(node *Node) error {
	sNode, err := k8sManager.client.CoreV1().Nodes().Get(context.Background(), node.name, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("warning: get k8s node failed: %v ", err)
	}
	pools := map[string]struct{}{}

	if sNode.Annotations != nil {
		if pAnnotation := strings.Split(sNode.Annotations[poolAnnotation], ","); len(pAnnotation) > 0 {
			for _, a := range pAnnotation {
				pools[a] = struct{}{}
			}
		}
	}

	// for range each pool annotation
	for p, _ := range pools {
		// judge whether the cpip exist
		if _, hasPoolCrd := n.pools[p]; hasPoolCrd {
			// judge whether the pool has ENI or secondaryIps
			hasENI := false
			hasIps := false
			for _, eni := range node.resource.Status.OpenStack.ENIs {
				if eni.Pool == p {
					hasENI = true
					if len(eni.SecondaryIPSets) > 0 {
						hasIps = true
						break
					}
				}
			}

			// judge whether the node has homologous crdPool
			if _, exist := node.pools[Pool(p)]; !exist {
				if hasIps {
					// If both ENI and pool annotation exist, create the crdPool and set pool status to Active
					node.pools[Pool(p)] = NewCrdPool(Pool(p), node, n.releaseExcessIPs, Active)
					err := k8sManager.UpdateCiliumIPPoolStatus(p, node.name, "Ready", "Created crd pool success.")
					if err != nil {
						log.Errorf("Update CiliumIPPool status failed, error is %s.", err)
					}
					continue
				}

				if hasENI {
					node.pools[Pool(p)] = NewCrdPool(Pool(p), node, n.releaseExcessIPs, WaitingForAllocate)
					err := k8sManager.UpdateCiliumIPPoolStatus(p, node.name, "NotReady", "Pool is not ready, is waiting for allocate.")
					if err != nil {
						log.Errorf("Update CiliumIPPool status failed, error is %s.", err)
					}
					continue
				}

				// upper pool limit
				if len(node.pools) == MaxPools {
					err := k8sManager.UpdateCiliumIPPoolStatus(p, node.name, "NotReady", "The node has reached the upper pool limit.")
					if err != nil {
						log.Errorf("Update CiliumIPPool status failed, error is %s.", err)
					}
					continue
				}

				limit, ok := limits.Get(node.resource.Spec.OpenStack.InstanceType)
				if !ok {
					log.Errorln("limit is not available")
					continue
				}

				// upper eni limit
				if len(node.resource.Status.OpenStack.ENIs) == limit.Adapters {
					err := k8sManager.UpdateCiliumIPPoolStatus(p, node.name, "NotReady", "The node has reached the upper eni limit.")
					if err != nil {
						log.Errorf("Update CiliumIPPool status failed, error is %s.", err)
					}
					continue
				}

				// Meet the crdPool creation requirements
				node.pools[Pool(p)] = NewCrdPool(Pool(p), node, n.releaseExcessIPs, WaitingForAllocate)
				err := k8sManager.UpdateCiliumIPPoolStatus(p, node.name, "NotReady", "Pool is not ready, is waiting for allocate.")
				if err != nil {
					log.Errorf("Update CiliumIPPool status failed, error is %s.", err)
				}

			}

			// rejudge whether the node's crdPool exist
			if pool, exist := node.pools[Pool(p)]; exist {
				if hasENI {
					if hasIps {
						pool.setPoolStatus(Active)
					}
					//  try 3 times when add finalizer flag failed
					retryCount := 3
				loop:
					err := k8sManager.AddFinalizerFlag(p, node.name)
					if err != nil {
						if retryCount > 0 {
							retryCount--
							goto loop
						}
						log.Errorf("failed to add finalizer flag %s on ciliumpodippool %s after 3 times retry, error is %s", node.name, p, err)
					}
				}
			}
		}
	}

	// if the node's crdPool exist, but pool annotation not exist, we should set the pool status to Recycling
	for p, crdPool := range node.pools {
		if _, exist := pools[p.String()]; !exist && crdPool.poolStatus() != Delete {
			crdPool.setPoolStatus(Recycling)
		}
	}

	labels := map[string]string{}

	// Only a pool in Active state can be labeled
	for name, p := range node.pools {
		if p.poolStatus() == Active {
			labels[poolLabel+"/"+string(name)] = "true"
		}
	}

	return k8sManager.LabelNodeWithPool(node.name, labels)
}
