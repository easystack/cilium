package ipam

import (
	"context"
	"fmt"
	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam/metrics"
	ipamStats "github.com/cilium/cilium/pkg/ipam/stats"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/math"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"
	"sync"
	"time"
)

type pool interface {
	maintainCRDIPPool(ctx context.Context) (poolMutated bool, err error)
	allocationNeeded() bool
	releaseNeeded() (needed bool)
	requirePoolMaintenance()
	waitingForMaintenance() bool
	GetAvailable() ipamTypes.AllocationMap
	getPreAllocate() int
	getMinAllocate() int
	getMaxAllocate() int
	getStatics() *Statistics
	recalculate(ipamTypes.AllocationMap, ipamStats.InterfaceStats)
	updateLastResync(syncTime time.Time)
	poolMaintenanceComplete()
	requireResync()
	allocateStaticIP(ip string, pool Pool) error
	requireSyncCsip()
	syncCsipComplete()
	waitingForSyncCsip() bool
	poolStatus() poolStatus
	setPoolStatus(s poolStatus)
}

type poolStatus int

const (
	Active poolStatus = iota
	Recycling
	Delete
)

const (
	// MaxPools limit the number of pool per node
	MaxPools = 5
)

// PoolStatistics represent the IP allocation statistics of a node
type PoolStatistics struct {
	// UsedIPs is the number of IPs currently in use
	UsedIPs int

	// AvailableIPs is the number of IPs currently allocated and available for assignment.
	AvailableIPs int

	// Capacity is the max inferred IPAM IP capacity for the node.
	// In theory, this provides an upper limit on the number of Cilium IPs that
	// this Node can support.
	Capacity int

	// NeededIPs is the number of IPs needed to reach the PreAllocate
	// watermwark
	NeededIPs int

	// ExcessIPs is the number of free IPs exceeding MaxAboveWatermark
	ExcessIPs int

	// RemainingInterfaces is the number of interfaces that can either be
	// allocated or have not yet exhausted the instance specific quota of
	// addresses
	RemainingInterfaces int

	// InterfaceCandidates is the number of attached interfaces with IPs
	// available for allocation.
	InterfaceCandidates int

	// EmptyInterfaceSlots is the number of empty interface slots available
	// for interfaces to be attached
	EmptyInterfaceSlots int

	// resyncNeeded is set to the current time when a resync with the EC2
	// API is required. The timestamp is required to ensure that this is
	// only reset if the resync started after the time stored in
	// resyncNeeded. This is needed because resyncs and allocations happen
	// in parallel.
	resyncNeeded time.Time

	// available is the map of IPs available to this node
	available ipamTypes.AllocationMap
}

func NewCrdPool(name Pool, node *Node, releaseExcessIPs bool, status poolStatus) pool {
	return &crdPool{
		name:                      name,
		node:                      node,
		stats:                     &Statistics{},
		available:                 map[string]ipamTypes.AllocationIP{},
		statistics:                PoolStatistics{},
		releaseExcessIPs:          releaseExcessIPs,
		status:                    status,
		waitingForPoolMaintenance: true,
	}
}

type crdPool struct {
	name Pool

	// stats provides accounting for various per node statistics
	stats *Statistics
	mutex sync.RWMutex

	releaseExcessIPs bool

	// lastMaxAdapterWarning is the timestamp when the last warning was
	// printed that this node is out of adapters
	lastMaxAdapterWarning time.Time

	node *Node

	// available is the map of IPs available to this pool
	available ipamTypes.AllocationMap

	// resyncNeeded is set to the current time when a resync with the EC2
	// API is required. The timestamp is required to ensure that this is
	// only reset if the resync started after the time stored in
	// resyncNeeded. This is needed because resyncs and allocations happen
	// in parallel.
	resyncNeeded time.Time

	// waitingForPoolMaintenance is true when the node is subject to an
	// IP allocation or release which must be performed before another
	// allocation or release can be attempted
	waitingForPoolMaintenance bool

	statistics PoolStatistics

	needSyncCsip bool

	status poolStatus
}

// maintainCRDIPPool attempts to allocate or release all required IPs to fulfill the needed gap.
// returns instanceMutated which tracks if state changed with the cloud provider and is used
// to determine if IPAM pool maintainer trigger func needs to be invoked.
func (p *crdPool) maintainCRDIPPool(ctx context.Context) (poolMutated bool, err error) {
	if p.status == Active {
		a, err := p.determinePoolMaintenanceAction()
		if err != nil {
			p.abortNoLongerExcessIPs(nil)
			return false, err
		}

		// Maintenance request has already been fulfilled
		if a == nil {
			p.abortNoLongerExcessIPs(nil)
			return false, nil
		}

		if instanceMutated, err := p.handleIPRelease(ctx, a); instanceMutated || err != nil {
			return instanceMutated, err
		}

		return p.handleMultiPoolIPAllocation(ctx, a)
	}

	if p.status == Recycling {
		existENIs := false
		for _, eni := range p.node.resource.Status.OpenStack.ENIs {
			if eni.Pool == p.name.String() {
				existENIs = true
				break
			}
		}
		if !existENIs && p.statistics.AvailableIPs == 0 {
			p.setPoolStatus(Delete)
			err := k8sManager.RemoveFinalizerFlag(string(p.name), p.node.name)
			if err != nil {
				return false, err
			}
			return false, nil
		}
		poolMutated, err = p.releaseAllPreallocateIPs(ctx)
		return
	}

	return false, nil
}

// releaseAllPreallocateIPs attempts to release all preallocate ips, but still reserve the ips which in use.
func (p *crdPool) releaseAllPreallocateIPs(ctx context.Context) (instanceMutated bool, err error) {
	scopedLog := p.logger()

	if !p.releaseExcessIPs {
		return false, nil
	}

	p.abortNoLongerExcessIPs(nil)

	stats := p.stats
	releaseCount := stats.AvailableIPs - stats.UsedIPs
	r := p.node.ops.PrepareIPRelease(releaseCount, scopedLog, p.name)

	return p.handleIPRelease(ctx, &maintenanceAction{release: r})
}

func (p *crdPool) determinePoolMaintenanceAction() (a *maintenanceAction, err error) {
	scopedLog := p.logger()

	a = &maintenanceAction{}
	stats := p.stats
	// Validate that the node still requires addresses to be released, the
	// request may have been resolved in the meantime.
	if p.releaseExcessIPs && stats.ExcessIPs > 0 {
		a.release = p.node.ops.PrepareIPRelease(stats.ExcessIPs, scopedLog, p.name)
		return a, nil
	}

	// Validate that the node still requires addresses to be allocated, the
	// request may have been resolved in the meantime.
	if stats.NeededIPs == 0 {
		return nil, nil
	}

	a.allocation, err = p.node.ops.PrepareIPAllocation(scopedLog, p.name)
	if err != nil {
		return nil, err
	}

	surgeAllocate := 0
	numPendingPods, err := getPendingPodCountByPool(p.node.name, p.name)
	if err != nil {
		if p.node.logLimiter.Allow() {
			scopedLog.WithError(err).Warningf("Unable to compute pending pods, will not surge-allocate")
		}
	} else if numPendingPods > stats.NeededIPs {
		surgeAllocate = numPendingPods - stats.NeededIPs
	}

	// handleIPAllocation() takes a min of MaxIPsToAllocate and IPs available for allocation on the interface.
	// This makes sure we don't try to allocate more than what's available.
	a.allocation.MaxIPsToAllocate = stats.NeededIPs + p.node.getMaxAboveWatermark() + surgeAllocate

	if a.allocation != nil {
		statistic := p.stats
		statistic.RemainingInterfaces = a.allocation.InterfaceCandidates + a.allocation.EmptyInterfaceSlots
		p.stats = statistic
		stats = p.stats
		scopedLog = scopedLog.WithFields(logrus.Fields{
			"selectedInterface":      a.allocation.InterfaceID,
			"selectedPoolID":         a.allocation.PoolID,
			"maxIPsToAllocate":       a.allocation.MaxIPsToAllocate,
			"availableForAllocation": a.allocation.AvailableForAllocation,
			"emptyInterfaceSlots":    a.allocation.EmptyInterfaceSlots,
		})
	}

	scopedLog.WithFields(logrus.Fields{
		"available":           stats.AvailableIPs,
		"used":                stats.UsedIPs,
		"neededIPs":           stats.NeededIPs,
		"remainingInterfaces": stats.RemainingInterfaces,
	}).Infof("Resolving IP deficit of node pool: %v", p.name)

	return a, nil
}

// handleMultiPoolIPAllocation allocates the necessary IPs needed to resolve deficit on the node.
// If existing interfaces don't have enough capacity, new interface would be created.
func (p *crdPool) handleMultiPoolIPAllocation(ctx context.Context, a *maintenanceAction) (poolMutated bool, err error) {
	scopedLog := p.logger()
	if a.allocation == nil {
		scopedLog.Debug("No allocation action required")
		return false, nil
	}

	// Assign needed addresses
	if a.allocation.AvailableForAllocation > 0 {
		a.allocation.AvailableForAllocation = math.IntMin(a.allocation.AvailableForAllocation, a.allocation.MaxIPsToAllocate)

		start := time.Now()
		err := p.node.ops.AllocateIPs(ctx, a.allocation, p.name)
		if err == nil {
			p.node.manager.metricsAPI.AllocationAttempt(allocateIP, success, string(a.allocation.PoolID), metrics.SinceInSeconds(start))
			p.node.manager.metricsAPI.AddIPAllocation(string(a.allocation.PoolID), int64(a.allocation.AvailableForAllocation))
			return true, nil
		}

		p.node.manager.metricsAPI.AllocationAttempt(allocateIP, failed, string(a.allocation.PoolID), metrics.SinceInSeconds(start))
		scopedLog.WithFields(logrus.Fields{
			"selectedInterface": a.allocation.InterfaceID,
			"ipsToAllocate":     a.allocation.AvailableForAllocation,
		}).WithError(err).Warning("Unable to assign additional IPs to interface, will create new interface")
	}

	return p.node.createInterface(ctx, a.allocation, p.name)
}

// handleIPRelease implements IP release handshake needed for releasing excess IPs on the node.
// Operator initiates the handshake after an IP remains unused and excess for more than the number of seconds configured
// by excess-ip-release-delay flag. Operator uses a map in ciliumnode's IPAM status field to exchange handshake
// information with the agent. Once the operator marks an IP for release, agent can either acknowledge or NACK IPs.
// If agent acknowledges, operator will release the IP and update the state to released. After the IP is removed from
// spec.ipam.pool and status is set to released, agent will remove the entry from map completing the handshake.
// Handshake is implemented with 4 states :
// * marked-for-release : Set by operator as possible candidate for IP
// * ready-for-release  : Acknowledged as safe to release by agent
// * do-not-release     : IP already in use / not owned by the node. Set by agent
// * released           : IP successfully released. Set by operator
//
// Handshake would be aborted if there are new allocations and the node doesn't have IPs in excess anymore.
func (p *crdPool) handleIPRelease(ctx context.Context, a *maintenanceAction) (instanceMutated bool, err error) {
	return p.node.handleIPRelease(ctx, a)
}

// abortNoLongerExcessIPs allows for aborting release of IP if new allocations on the node result in a change of excess
// count or the interface selected for release.
func (p *crdPool) abortNoLongerExcessIPs(excessMap map[string]bool) {
	p.node.abortNoLongerExcessIPs(excessMap)
}

// getPendingPodCountByPool computes the number of pods in pending state on a given node. watchers.PodStore is assumed to be
// initialized before this function is called.
func getPendingPodCountByPool(nodeName string, pool Pool) (int, error) {
	pendingPods := 0
	if watchers.PodStore == nil {
		return pendingPods, fmt.Errorf("pod store uninitialized")
	}
	values, err := watchers.PodStore.(cache.Indexer).ByIndex(watchers.PodNodeNameIndex, nodeName)
	if err != nil {
		return pendingPods, fmt.Errorf("unable to access pod to node name index: %w", err)
	}
	for _, pod := range values {
		p := pod.(*v1.Pod)
		if p.Status.Phase == v1.PodPending {
			if p.Annotations != nil && p.Annotations["ipam.cilium.io/ip-pool"] == string(pool) {
				pendingPods++
			}
		}
	}
	return pendingPods, nil
}

func (p *crdPool) recalculate(allocate ipamTypes.AllocationMap, stats ipamStats.InterfaceStats) {
	scopedLog := p.logger()
	maxAllocate := p.getMaxAllocate()
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.available = allocate
	if p.node.resource != nil {
		p.stats.UsedIPs = len(p.node.resource.Status.IPAM.PoolUsed[p.name.String()])
	}

	// Get used IP count with prefixes included
	usedIPForExcessCalc := p.stats.UsedIPs
	if p.node.ops.IsPrefixDelegated() {
		usedIPForExcessCalc = p.node.ops.GetPoolUsedIPWithPrefixes(p.name.String())
	}

	p.stats.AvailableIPs = len(p.available)
	if p.status == Active {
		p.stats.NeededIPs = calculateNeededIPs(p.stats.AvailableIPs, p.stats.UsedIPs, p.getPreAllocate(), p.getMinAllocate(), maxAllocate)
	} else {
		p.stats.NeededIPs = 0
	}
	p.stats.ExcessIPs = calculateExcessIPs(p.stats.AvailableIPs, usedIPForExcessCalc, p.getPreAllocate(), p.getMinAllocate(), p.node.getMaxAboveWatermark())
	p.stats.RemainingInterfaces = stats.RemainingAvailableInterfaceCount
	p.stats.Capacity = stats.NodeCapacity

	scopedLog.WithFields(logrus.Fields{
		"available":                 p.stats.AvailableIPs,
		"used":                      p.stats.UsedIPs,
		"toAlloc":                   p.stats.NeededIPs,
		"toRelease":                 p.stats.ExcessIPs,
		"waitingForPoolMaintenance": p.waitingForPoolMaintenance,
		"resyncNeeded":              p.resyncNeeded,
		"remainingInterfaces":       stats.RemainingAvailableInterfaceCount,
	}).Debugf("Recalculated needed addresses pool: %v", p.name)
}

// getPreAllocate returns the pre-allocation setting for a crd pool
//
// n.mutex must be held when calling this function
func (p *crdPool) getPreAllocate() int {
	return defaults.IPAMPreAllocation
}

// getMinAllocate returns the minimum-allocation setting of an AWS node
//
// n.mutex must be held when calling this function
func (p *crdPool) getMinAllocate() int {
	return p.node.resource.Spec.IPAM.MinAllocate
}

// getMaxAllocate returns the maximum-allocation setting of a pool
func (p *crdPool) getMaxAllocate() int {
	instanceMax := p.node.ops.GetMaximumAllocatableIPv4()
	if p.node.resource.Spec.IPAM.MaxAllocate > 0 {
		if p.node.resource.Spec.IPAM.MaxAllocate > instanceMax {
			p.loggerLocked().Warningf("max-allocate (%d) is higher than the instance type limits (%d)", p.node.resource.Spec.IPAM.MaxAllocate, instanceMax)
		}
		return p.node.resource.Spec.IPAM.MaxAllocate
	}

	return instanceMax
}

// allocationNeeded returns true if this crdPool requires IPs to be allocated
func (p *crdPool) allocationNeeded() (needed bool) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	needed = !p.waitingForPoolMaintenance && p.resyncNeeded.IsZero() && p.stats.NeededIPs > 0
	return
}

func (p *crdPool) requirePoolMaintenance() {
	p.mutex.Lock()
	p.waitingForPoolMaintenance = true
	p.mutex.Unlock()
}

func (p *crdPool) releaseNeeded() (needed bool) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	needed = p.releaseExcessIPs && !p.waitingForPoolMaintenance && p.resyncNeeded.IsZero() && p.stats.ExcessIPs > 0
	if p.node.resource != nil {
		releaseInProgress := len(p.node.resource.Status.IPAM.ReleaseIPs) > 0
		needed = needed || releaseInProgress || p.status != Active
	}
	return
}

func (p *crdPool) GetAvailable() ipamTypes.AllocationMap {
	return p.available
}

func (p *crdPool) waitingForMaintenance() bool {
	return p.waitingForPoolMaintenance
}

func (p *crdPool) getStatics() *Statistics {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.stats
}

func (p *crdPool) logger() *logrus.Entry {
	if p == nil {
		return log
	}

	return p.loggerLocked()
}

func (p *crdPool) loggerLocked() (logger *logrus.Entry) {
	logger = log

	if p != nil {
		logger = logger.WithField(fieldName, "pool: "+p.name)
		if p.node.resource != nil {
			logger = logger.WithField("instanceID", p.node.resource.InstanceID())
		}
	}
	return
}

func (p *crdPool) poolMaintenanceComplete() {
	p.mutex.Lock()
	p.waitingForPoolMaintenance = false
	defer p.mutex.Unlock()
}

func (p *crdPool) updateLastResync(syncTime time.Time) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if syncTime.After(p.resyncNeeded) {
		p.loggerLocked().Debug("Resetting resyncNeeded")
		p.resyncNeeded = time.Time{}
	}
}

func (p *crdPool) requireResync() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.resyncNeeded = time.Now()
}

func (p *crdPool) allocateStaticIP(ip string, pool Pool) error {
	err, stats := p.node.AllocateStaticIP(ip, pool)
	if err != nil {
		return err
	}
	if stats != nil {
		p.stats = stats
	}
	return nil
}

func (p *crdPool) requireSyncCsip() {
	p.needSyncCsip = true
}

func (p *crdPool) syncCsipComplete() {
	p.mutex.Lock()
	p.needSyncCsip = false
	p.mutex.Unlock()

}

func (p *crdPool) waitingForSyncCsip() bool {
	return p.needSyncCsip
}

func (p *crdPool) poolStatus() poolStatus {
	return p.status
}

func (p *crdPool) setPoolStatus(s poolStatus) {
	p.mutex.Lock()
	p.status = s
	p.mutex.Unlock()
}
