// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
)

type poolPair struct {
	v4 *podCIDRPool
	v6 *podCIDRPool
}

type preAllocValue int
type preAllocMap map[string]preAllocValue

func parsePreAllocMap(conf map[string]string) (preAllocMap, error) {
	m := make(map[string]preAllocValue, len(conf))
	for pool, s := range conf {
		value, err := strconv.ParseInt(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid pre-alloc value for pool %q: %w", pool, err)
		}
		m[pool] = preAllocValue(value)
	}

	return m, nil
}

type clusterPoolManager struct {
	mutex *lock.Mutex
	conf  Configuration
	owner Owner

	preallocMap  preAllocMap
	pools        map[string]*poolPair
	poolsUpdated chan struct{}

	node *ciliumv2.CiliumNode

	controller  *controller.Manager
	k8sUpdater  *trigger.Trigger
	nodeUpdater nodeUpdater

	finishedRestore bool
}

var _ Allocator = (*clusterPoolV2Allocator)(nil)

func newClusterPoolManager(conf Configuration, nodeWatcher nodeWatcher, owner Owner, clientset nodeUpdater) *clusterPoolManager {
	preallocMap, err := parsePreAllocMap(option.Config.IPAMClusterPoolNodePreAlloc)
	if err != nil {
		log.WithError(err).Fatalf("Invalid %s flag value", option.IPAMClusterPoolNodePreAlloc)
	}

	k8sController := controller.NewManager()
	k8sUpdater, err := trigger.NewTrigger(trigger.Parameters{
		MinInterval: 15 * time.Second,
		TriggerFunc: func(reasons []string) {
			k8sController.TriggerController(clusterPoolStatusControllerName)
		},
		Name: clusterPoolStatusTriggerName,
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize CiliumNode synchronization trigger")
	}

	c := &clusterPoolManager{
		mutex:           &lock.Mutex{},
		owner:           owner,
		conf:            conf,
		preallocMap:     preallocMap,
		pools:           map[string]*poolPair{},
		poolsUpdated:    make(chan struct{}, 1),
		node:            nil,
		controller:      k8sController,
		k8sUpdater:      k8sUpdater,
		nodeUpdater:     clientset,
		finishedRestore: false,
	}

	// Subscribe to CiliumNode updates
	nodeWatcher.RegisterCiliumNodeSubscriber(c)
	owner.UpdateCiliumNodeResource()

	c.waitForAllPools()

	return c
}

func (c *clusterPoolManager) waitForAllPools() {
	ctx := context.Background()
	for pool := range c.preallocMap {
		if c.conf.IPv4Enabled() {
			c.waitForPool(ctx, IPv4, pool)
		}
		if c.conf.IPv6Enabled() {
			c.waitForPool(ctx, IPv6, pool)
		}
	}
}

func (c *clusterPoolManager) waitForPool(ctx context.Context, family Family, poolName string) {
	timer, stop := inctimer.New()
	defer stop()
	for {
		c.mutex.Lock()
		switch family {
		case IPv4:
			if p, ok := c.pools[poolName]; ok && p.v4 != nil && p.v4.hasAvailableIPs() {
				c.mutex.Unlock()
				return
			}
		case IPv6:
			if p, ok := c.pools[poolName]; ok && p.v6 != nil && p.v6.hasAvailableIPs() {
				c.mutex.Unlock()
				return
			}
		}
		c.mutex.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-c.poolsUpdated:
			continue
		case <-timer.After(5 * time.Second):
			log.WithFields(logrus.Fields{
				logfields.HelpMessage: "Check if cilium-operator pod is running and does not have any warnings or error messages.",
				logfields.Family:      family,
			}).Info("Waiting for pod CIDR pool to become available")
		}
	}
}

func (c *clusterPoolManager) ciliumNodeUpdated(newNode *ciliumv2.CiliumNode) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// restore state from previous agent run, this collects (previously)
	// released CIDRs and ensures they are not used for allocation in this instance either
	if c.node == nil {
		// This enables the upstream sync controller. It requires c.node to be populated.
		// Note: The controller will only run after c.mutex is unlocked
		c.controller.UpdateController(clusterPoolStatusControllerName, controller.ControllerParams{
			DoFunc: c.updateCiliumNode,
		})
	}

	for _, pool := range newNode.Spec.IPAM.Pools.Allocated {
		c.upsertPoolLocked(pool.Pool, pool.CIDRs)
	}

	c.node = newNode
}

func neededIPCeil(numIP int, preAlloc int) int {
	quotient := numIP / preAlloc
	rem := numIP % preAlloc
	if rem > 0 {
		return (quotient + 2) * preAlloc
	}
	return (quotient + 1) * preAlloc
}

func (c *clusterPoolManager) updateCiliumNode(ctx context.Context) error {
	c.mutex.Lock()
	newNode := c.node.DeepCopy()
	requested := []types.IPAMPoolRequest{}
	allocated := []types.IPAMPoolAllocation{}

	// Only pools present in cluster-pool-node-pre-alloc can be requested
	for poolName, preAlloc := range c.preallocMap {
		var neededIPv4, neededIPv6 int
		pool, ok := c.pools[poolName]
		if ok {
			if pool.v4 != nil {
				neededIPv4 = pool.v4.inUseIPCount()
			}
			if pool.v6 != nil {
				neededIPv6 = pool.v6.inUseIPCount()
			}
		}

		if c.conf.IPv4Enabled() {
			neededIPv4 = neededIPCeil(neededIPv4, int(preAlloc))
			if ok && pool.v4 != nil {
				pool.v4.releaseExcessCIDRsV2(neededIPv4)
			}
		}
		if c.conf.IPv6Enabled() {
			neededIPv6 = neededIPCeil(neededIPv6, int(preAlloc))
			if ok && pool.v6 != nil {
				pool.v6.releaseExcessCIDRsV2(neededIPv6)
			}
		}

		requested = append(requested, types.IPAMPoolRequest{
			Pool: poolName,
			Needed: types.IPAMPoolDemand{
				IPv4Addrs: neededIPv4,
				IPv6Addrs: neededIPv6,
			},
		})
	}

	// Write in-use pools to podCIDR. This removes any released pod CIDRs
	for poolName, pool := range c.pools {
		cidrs := []string{}
		if pool.v4 != nil {
			v4CIDRs := pool.v4.inUsePodCIDRs()
			sort.Strings(v4CIDRs)
			cidrs = append(cidrs, v4CIDRs...)
		}
		if pool.v6 != nil {
			v6CIDRs := pool.v6.inUsePodCIDRs()
			sort.Strings(v6CIDRs)
			cidrs = append(cidrs, v6CIDRs...)
		}

		allocated = append(allocated, types.IPAMPoolAllocation{
			Pool:  poolName,
			CIDRs: cidrs,
		})
	}

	sort.Slice(requested, func(i, j int) bool {
		return requested[i].Pool > requested[j].Pool
	})
	sort.Slice(allocated, func(i, j int) bool {
		return allocated[i].Pool > allocated[j].Pool
	})
	newNode.Spec.IPAM.Pools.Requested = requested
	newNode.Spec.IPAM.Pools.Allocated = allocated

	c.mutex.Unlock()

	var controllerErr error
	if !newNode.Spec.IPAM.DeepEqual(&c.node.Spec.IPAM) {
		_, err := c.nodeUpdater.Update(ctx, newNode, metav1.UpdateOptions{})
		if err != nil {
			controllerErr = multierr.Append(controllerErr, fmt.Errorf("failed to update node spec: %w", err))
		}
	}

	return controllerErr
}

func (c *clusterPoolManager) upsertPoolLocked(poolName string, podCIDRs []string) {
	pool, ok := c.pools[poolName]
	if !ok {
		pool = &poolPair{}
		if c.conf.IPv4Enabled() {
			pool.v4 = newPodCIDRPool(nil)
		}
		if c.conf.IPv6Enabled() {
			pool.v6 = newPodCIDRPool(nil)
		}
	}

	var ipv4PodCIDRs, ipv6PodCIDRs []string
	for _, podCIDR := range podCIDRs {
		switch podCIDRFamily(podCIDR) {
		case IPv4:
			ipv4PodCIDRs = append(ipv4PodCIDRs, podCIDR)
		case IPv6:
			ipv6PodCIDRs = append(ipv6PodCIDRs, podCIDR)
		}
	}

	if pool.v4 != nil {
		pool.v4.updatePool(ipv4PodCIDRs)
	}
	if pool.v6 != nil {
		pool.v6.updatePool(ipv6PodCIDRs)
	}

	c.pools[poolName] = pool

	select {
	case c.poolsUpdated <- struct{}{}:
	default:
	}
}

func (c *clusterPoolManager) OnAddCiliumNode(node *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	if k8s.IsLocalCiliumNode(node) {
		c.ciliumNodeUpdated(node)
	}

	return nil
}

func (c *clusterPoolManager) OnUpdateCiliumNode(oldNode, newNode *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	if k8s.IsLocalCiliumNode(newNode) {
		c.ciliumNodeUpdated(newNode)
	}

	return nil
}

func (c *clusterPoolManager) OnDeleteCiliumNode(node *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	if k8s.IsLocalCiliumNode(node) {
		log.WithField(logfields.Node, node).Warning("Local CiliumNode deleted. IPAM will continue on last seen version")
	}

	return nil
}

func (c *clusterPoolManager) dump(family Family) (allocated map[string]string, status string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	allocated = map[string]string{}
	for poolName, pool := range c.pools {
		var p *podCIDRPool
		switch family {
		case IPv4:
			p = pool.v4
		case IPv6:
			p = pool.v6
		}
		if p == nil {
			return nil, fmt.Sprintf("family %q not supported", family)
		}

		ipToOwner, _, _, _, err := p.dump()
		if err != nil {
			return nil, fmt.Sprintf("error: %s", err)
		}

		ipPrefix := ""
		if poolName != PoolDefault.String() {
			ipPrefix = poolName + "/"
		}

		for ip, owner := range ipToOwner {
			allocated[ipPrefix+ip] = owner
		}
	}

	return allocated, fmt.Sprintf("%d IPAM pool(s) available", len(c.pools))
}

func (c *clusterPoolManager) poolByFamilyLocked(poolName string, family Family) *podCIDRPool {
	switch family {
	case IPv4:
		pair, ok := c.pools[poolName]
		if ok {
			return pair.v4
		}
	case IPv6:
		pair, ok := c.pools[poolName]
		if ok {
			return pair.v6
		}
	}

	return nil
}

func (c *clusterPoolManager) allocateNext(owner string, poolName Pool, family Family, syncUpstream bool) (*AllocationResult, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	pool := c.poolByFamilyLocked(poolName.String(), family)
	if pool == nil {
		return nil, fmt.Errorf("unable to allocate from unknown pool %q (family %s)", poolName, family)
	}

	ip, err := pool.allocateNext()
	if err != nil {
		return nil, err
	}

	if syncUpstream {
		c.k8sUpdater.TriggerWithReason("allocation of next IP")
	}
	return &AllocationResult{IP: ip}, nil
}

func (c *clusterPoolManager) allocateIP(ip net.IP, owner string, poolName Pool, family Family, syncUpstream bool) (*AllocationResult, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	pool := c.poolByFamilyLocked(poolName.String(), family)
	if pool == nil {
		return nil, fmt.Errorf("unable to reserve IP %s from unknown pool %q (family %s)", ip, poolName, family)
	}

	err := pool.allocate(ip)
	if err != nil {
		return nil, err
	}

	if syncUpstream {
		c.k8sUpdater.TriggerWithReason("allocation of IP")
	}
	return &AllocationResult{IP: ip}, nil
}

func (c *clusterPoolManager) releaseIP(ip net.IP, poolName Pool, family Family, upstreamSync bool) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	pool := c.poolByFamilyLocked(poolName.String(), family)
	if pool == nil {
		return fmt.Errorf("unable to release IP %s of unknown pool %q (family %s)", ip, poolName, family)
	}

	err := pool.release(ip)
	if err == nil && upstreamSync {
		c.k8sUpdater.TriggerWithReason("release of IP")
	}
	return err
}

func (c *clusterPoolManager) Allocator(family Family) Allocator {
	return &clusterPoolV2Allocator{
		manager: c,
		family:  family,
	}
}

type clusterPoolV2Allocator struct {
	manager *clusterPoolManager
	family  Family
}

func (c *clusterPoolV2Allocator) Allocate(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateIP(ip, owner, pool, c.family, true)
}

func (c *clusterPoolV2Allocator) AllocateWithoutSyncUpstream(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateIP(ip, owner, pool, c.family, false)
}

func (c *clusterPoolV2Allocator) Release(ip net.IP, pool Pool) error {
	return c.manager.releaseIP(ip, pool, c.family, true)
}

func (c *clusterPoolV2Allocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateNext(owner, pool, c.family, true)
}

func (c *clusterPoolV2Allocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateNext(owner, pool, c.family, false)
}

func (c *clusterPoolV2Allocator) Dump() (map[string]string, string) {
	return c.manager.dump(c.family)
}

func (c *clusterPoolV2Allocator) RestoreFinished() {}
