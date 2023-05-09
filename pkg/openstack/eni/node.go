// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/math"
	"github.com/cilium/cilium/pkg/openstack/eni/limits"
	eniTypes "github.com/cilium/cilium/pkg/openstack/eni/types"
	"github.com/cilium/cilium/pkg/openstack/utils"
)

// The following error constants represent the error conditions for
// CreateInterface without additional context embedded in order to make them
// usable for metrics accounting purposes.
const (
	errUnableToDetermineLimits   = "unable to determine limits"
	unableToDetermineLimits      = "unableToDetermineLimits"
	errUnableToGetSecurityGroups = "unable to get security groups"
	unableToGetSecurityGroups    = "unableToGetSecurityGroups"
	errUnableToCreateENI         = "unable to create ENI"
	unableToCreateENI            = "unableToCreateENI"
	errUnableToAttachENI         = "unable to attach ENI"
	unableToAttachENI            = "unableToAttachENI"
	unableToFindSubnet           = "unableToFindSubnet"
	unableToTagENI               = "unableToTagENI"
)

const (
	maxENIIPCreate = 10

	maxENIPerNode = 50
)

type Node struct {
	// node contains the general purpose fields of a node
	node *ipam.Node

	// mutex protects members below this field
	mutex lock.RWMutex

	// enis is the list of ENIs attached to the node indexed by ENI ID.
	// Protected by Node.mutex.
	enis map[string]eniTypes.ENI

	// k8sObj is the CiliumNode custom resource representing the node
	k8sObj *v2.CiliumNode

	// manager is the ecs node manager responsible for this node
	manager *InstancesManager

	// instanceID of the node
	instanceID string
}

// UpdatedNode is called when an update to the CiliumNode is received.
func (n *Node) UpdatedNode(obj *v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.k8sObj = obj
}

// PopulateStatusFields fills in the status field of the CiliumNode custom
// resource with ENI specific information
func (n *Node) PopulateStatusFields(resource *v2.CiliumNode) {
	resource.Status.OpenStack.ENIs = map[string]eniTypes.ENI{}

	n.manager.ForeachInstance(n.node.InstanceID(),
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			log.Infof("######## Populate Status eni details is %+v", e)
			if ok {
				resource.Status.OpenStack.ENIs[interfaceID] = *e.DeepCopy()
			}
			return nil
		})
	return
}

// CreateInterface creates an additional interface with the instance and
// attaches it to the instance as specified by the CiliumNode. neededAddresses
// of secondary IPs are assigned to the interface up to the maximum number of
// addresses as allowed by the instance.
func (n *Node) CreateInterface(ctx context.Context, allocation *ipam.AllocationAction, scopedLog *logrus.Entry) (int, string, error) {
	scopedLog.Infof("@@@@@@@@@@@@@@@@@@@ Do Create interface")
	limits, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return 0, unableToDetermineLimits, fmt.Errorf(errUnableToDetermineLimits)
	}

	n.mutex.RLock()
	resource := *n.k8sObj
	n.mutex.RUnlock()

	// Must allocate secondary ENI IPs as needed, up to ENI instance limit
	toAllocate := math.IntMin(allocation.MaxIPsToAllocate, limits.IPv4)
	toAllocate = math.IntMin(maxENIIPCreate, toAllocate) // in first alloc no more than 10
	// Validate whether request has already been fulfilled in the meantime
	if toAllocate == 0 {
		return 0, "", nil
	}

	scopedLog.Infof("@@@@@@@@@@@@@@@@@@@ Do Create interface, openstack config is %+v", resource.Spec.OpenStack)
	subnet := n.findSuitableSubnet(resource.Spec.OpenStack, limits)
	scopedLog.Infof("@@@@@@@@@@@@@@@@ Find subnet: %+v", subnet)
	if subnet == nil {
		return 0,
			unableToFindSubnet,
			fmt.Errorf(
				"No matching subnet available for interface creation (VPC=%s AZ=%s SubnetID=%s)",
				resource.Spec.OpenStack.VPCID,
				resource.Spec.OpenStack.AvailabilityZone,
				resource.Spec.OpenStack.SubnetID,
			)
	}
	allocation.PoolID = ipamTypes.PoolID(subnet.ID)

	securityGroupIDs, err := n.getSecurityGroupIDs(ctx, resource.Spec.OpenStack)
	if err != nil {
		return 0,
			unableToGetSecurityGroups,
			fmt.Errorf("%s %s", errUnableToGetSecurityGroups, err)
	}

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"securityGroupIDs": securityGroupIDs,
		"subnet":           subnet.ID,
		"toAllocate":       toAllocate,
	})
	scopedLog.Info("No more IPs available, creating new ENI")

	instanceID := n.node.InstanceID()
	netID := resource.Spec.OpenStack.VPCID
	eniID, eni, err := n.manager.api.CreateNetworkInterface(ctx, subnet.ID, netID, instanceID, securityGroupIDs)
	if err != nil {
		return 0, unableToCreateENI, fmt.Errorf("%s %s", errUnableToCreateENI, err)
	}

	scopedLog = scopedLog.WithField(fieldENIID, eniID)
	scopedLog.Info("Created new ENI")

	if subnet.CIDR != nil {
		eni.Subnet.CIDR = subnet.CIDR.String()
	}

	err = n.manager.api.AttachNetworkInterface(ctx, instanceID, eniID)
	if err != nil {
		err = n.manager.api.DeleteNetworkInterface(ctx, eniID)
		if err != nil {
			scopedLog.Errorf("Failed to release ENI after failure to attach, %s", err.Error())
		}
		return 0, unableToAttachENI, fmt.Errorf("%s %s", errUnableToAttachENI, err)
	}

	index, err := n.allocENIIndex()
	if err != nil {
		scopedLog.WithField("instanceID", instanceID).Error(err)
		return 0, "Failed to allocate eni index", err
	}
	scopedLog.Info("########### got index is %d", index)
	err = n.manager.api.AddTagToNetworkInterface(ctx, eniID, utils.FillTagWithENIIndex(index))
	if err != nil {
		scopedLog.Errorf("########### Failed to add tag with error: %+v, %s", err, err)
		err = n.manager.api.DetachNetworkInterface(ctx, instanceID, eniID)
		if err != nil {
			scopedLog.Errorf("Failed to detach ENI after failure to tag index, %s", err.Error())
		}
		err = n.manager.api.DeleteNetworkInterface(ctx, eniID)
		if err != nil {
			scopedLog.Errorf("Failed to release ENI after failure to tag index, %s", err.Error())
		}
		return 0, unableToTagENI, fmt.Errorf("%s %s", unableToTagENI, err)
	}

	n.enis[eniID] = *eni
	scopedLog.Info("Attached ENI to instance with index:%d", index)

	// Add the information of the created ENI to the instances manager
	n.manager.UpdateENI(instanceID, eni)
	return toAllocate, "", nil
}

// ResyncInterfacesAndIPs is called to retrieve and ENIs and IPs as known to
// the OpenStack API and return them
func (n *Node) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry) (available ipamTypes.AllocationMap, remainAvailableENIsCount int, err error) {
	limits, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return nil, -1, fmt.Errorf(errUnableToDetermineLimits)
	}

	instanceID := n.node.InstanceID()
	available = ipamTypes.AllocationMap{}

	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.enis = map[string]eniTypes.ENI{}
	scopedLog.Infof("!!!!!!!!!!!!!!!!!! Do Resync nics and ips, instanceID is %s, limits: %+v, available is %t", instanceID, limits, limitsAvailable)

	n.manager.ForeachInstance(instanceID,
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			scopedLog.Infof("!!!!!!!!!!!! instance ENI is %+v, ok is %t", e, ok)
			if !ok {
				scopedLog.Infof("!!!!!!!!!!!! not here !!!!!!!!!!!")
				return nil
			}

			n.enis[e.ID] = *e

			if utils.IsExcludedByTags(e.Tags) {
				scopedLog.Infof("!!!!!!!!!!!! ENI %s is excluded by tags in Resync functions", e.ID)
				return nil
			}

			availableOnENI := math.IntMax(limits.IPv4-len(e.SecondaryIPSets), 0)
			if availableOnENI > 0 {
				remainAvailableENIsCount++
			}

			for _, ip := range e.SecondaryIPSets {
				available[ip.IpAddress] = ipamTypes.AllocationIP{Resource: e.ID}
			}

			return nil
		})
	enis := len(n.enis)

	// An ECS instance has at least one ENI attached, no ENI found implies instance not found.
	if enis == 0 {
		scopedLog.Warning("Instance not found! Please delete corresponding ciliumnode if instance has already been deleted.")
		return nil, -1, fmt.Errorf("unable to retrieve ENIs")
	}

	remainAvailableENIsCount += limits.Adapters - len(n.enis)

	scopedLog.Infof("!!!!!!!!!!!! ResyncInterfacesAndIPs result, remainAvailableENIsCount is %d, available is %+v", remainAvailableENIsCount, available)
	return available, remainAvailableENIsCount, nil
}

// PrepareIPAllocation returns the number of ENI IPs and interfaces that can be
// allocated/created.
func (n *Node) PrepareIPAllocation(scopedLog *logrus.Entry) (*ipam.AllocationAction, error) {
	l, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return nil, fmt.Errorf(errUnableToDetermineLimits)
	}
	a := &ipam.AllocationAction{}

	n.mutex.RLock()
	defer n.mutex.RUnlock()

	for key, e := range n.enis {
		scopedLog.Infof("@@@@@@@@@@@@@@@@ Do prepare ip allocation for node: %s, n is %+v, eni type is %s, detail is %+v", n.node.InstanceID(), n, e.Type, e)
		scopedLog.WithFields(logrus.Fields{
			fieldENIID:  e.ID,
			"ipv4Limit": l.IPv4,
			"allocated": len(e.SecondaryIPSets),
		}).Debug("Considering ENI for allocation")

		if utils.IsExcludedByTags(e.Tags) {
			scopedLog.Infof("!!!!!!!!!!!! ENI %s is excluded by tags in PrepareIPAllocation func", e.ID)
			continue
		}

		availableOnENI := math.IntMax(l.IPv4-len(e.SecondaryIPSets), 0)
		if availableOnENI <= 0 {
			continue
		} else {
			a.InterfaceCandidates++
		}

		scopedLog.WithFields(logrus.Fields{
			fieldENIID:       e.ID,
			"availableOnENI": availableOnENI,
		}).Debug("ENI has IPs available")

		if subnet := n.manager.GetSubnet(e.Subnet.ID); subnet != nil {
			if a.InterfaceID == "" {
				scopedLog.WithFields(logrus.Fields{
					"subnetID":           e.Subnet.ID,
					"availableAddresses": subnet.AvailableAddresses,
				}).Debug("Subnet has IPs available")

				a.InterfaceID = key
				a.PoolID = ipamTypes.PoolID(subnet.ID)
				a.AvailableForAllocation = math.IntMin(subnet.AvailableAddresses, availableOnENI)
			}
		}
	}
	a.EmptyInterfaceSlots = l.Adapters - len(n.enis)
	scopedLog.Infof("@@@@@@@@@@@@@@@@ Do prepare ip allocation, result is %+v", a)
	return a, nil
}

// AllocateIPs performs the ENI allocation operation
func (n *Node) AllocateIPs(ctx context.Context, a *ipam.AllocationAction) error {
	log.Infof("@@@@@@@@@@@@@@@@@@@ Do Allocate IPs.....")
	_, err := n.manager.api.AssignPrivateIPAddresses(ctx, a.InterfaceID, a.AvailableForAllocation)
	return err
}

// PrepareIPRelease prepares the release of ENI IPs.
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *logrus.Entry) *ipam.ReleaseAction {
	r := &ipam.ReleaseAction{}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	// Iterate over ENIs on this node, select the ENI with the most
	// addresses available for release
	for key, e := range n.enis {
		scopedLog.WithFields(logrus.Fields{
			fieldENIID:     e.ID,
			"numAddresses": len(e.SecondaryIPSets),
		}).Debug("Considering ENI for IP release")

		if e.Type != eniTypes.ENITypePrimary {
			continue
		}

		if utils.IsExcludedByTags(e.Tags) {
			scopedLog.Infof("!!!!!!!!!!!! ENI %s is excluded by tags in PrepareIPRelease func", e.ID)
			continue
		}

		// Count free IP addresses on this ENI
		ipsOnENI := n.k8sObj.Status.OpenStack.ENIs[e.ID].SecondaryIPSets
		freeIpsOnENI := []string{}
		for _, ip := range ipsOnENI {
			_, ipUsed := n.k8sObj.Status.IPAM.Used[ip.IpAddress]
			if !ipUsed {
				freeIpsOnENI = append(freeIpsOnENI, ip.IpAddress)
			}
		}
		freeOnENICount := len(freeIpsOnENI)

		if freeOnENICount <= 0 {
			continue
		}

		scopedLog.WithFields(logrus.Fields{
			fieldENIID:       e.ID,
			"excessIPs":      excessIPs,
			"freeOnENICount": freeOnENICount,
		}).Debug("ENI has unused IPs that can be released")
		maxReleaseOnENI := math.IntMin(freeOnENICount, excessIPs)

		r.InterfaceID = key
		r.PoolID = ipamTypes.PoolID(e.VPC.ID)
		r.IPsToRelease = freeIpsOnENI[:maxReleaseOnENI]
	}

	return r
}

// ReleaseIPs performs the ENI IP release operation
func (n *Node) ReleaseIPs(ctx context.Context, r *ipam.ReleaseAction) error {
	return n.manager.api.UnassignPrivateIPAddresses(ctx, r.InterfaceID, r.IPsToRelease)
}

// GetMaximumAllocatableIPv4 returns the maximum amount of IPv4 addresses
// that can be allocated to the instance
func (n *Node) GetMaximumAllocatableIPv4() int {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	// Retrieve l for the instance type
	l, limitsAvailable := n.getLimitsLocked()
	if !limitsAvailable {
		return 0
	}

	// Return the maximum amount of IP addresses allocatable on the instance
	// reserve Primary eni
	return (l.Adapters - 1) * l.IPv4
}

// GetMinimumAllocatableIPv4 returns the minimum amount of IPv4 addresses that
// must be allocated to the instance.
func (n *Node) GetMinimumAllocatableIPv4() int {
	return defaults.IPAMPreAllocation
}

func (n *Node) loggerLocked() *logrus.Entry {
	if n == nil || n.instanceID == "" {
		return log
	}

	return log.WithField("instanceID", n.instanceID)
}

func (n *Node) IsPrefixDelegated() bool {
	return false
}

func (n *Node) GetUsedIPWithPrefixes() int {
	if n.k8sObj == nil {
		return 0
	}
	return len(n.k8sObj.Status.IPAM.Used)
}

// getLimits returns the interface and IP limits of this node
func (n *Node) getLimits() (ipamTypes.Limits, bool) {
	n.mutex.RLock()
	l, b := n.getLimitsLocked()
	n.mutex.RUnlock()
	return l, b
}

// getLimitsLocked is the same function as getLimits, but assumes the n.mutex
// is read locked.
func (n *Node) getLimitsLocked() (ipamTypes.Limits, bool) {
	return limits.Get(n.k8sObj.Spec.OpenStack.InstanceType)
}

func (n *Node) getSecurityGroupIDs(ctx context.Context, eniSpec eniTypes.Spec) ([]string, error) {
	// ENI must have at least one security group
	// 1. use security group defined by user
	// 2. use security group used by primary ENI (eth0)

	if len(eniSpec.SecurityGroups) > 0 {
		return eniSpec.SecurityGroups, nil
	}

	var securityGroups []string

	n.manager.ForeachInstance(n.node.InstanceID(),
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			log.Infof("@@@@@@@@@@@ eni detail is %+v", e)
			if ok && e.Type == eniTypes.ENITypePrimary {
				securityGroups = append(securityGroups, e.SecurityGroups...)
			}
			return nil
		})

	if len(securityGroups) <= 0 {
		return nil, fmt.Errorf("failed to get security group ids")
	}

	return securityGroups, nil
}

// findSuitableSubnet attempts to find a subnet to allocate an ENI in according to the following heuristic.
//  0. In general, the subnet has to be in the same VPC and match the availability zone of the
//     node. If there are multiple candidates, we choose the subnet with the most addresses
//     available.
//  1. If we have explicit ID or tag constraints, chose a matching subnet. ID constraints take
//     precedence.
//  2. If we have no explicit constraints, try to use the subnet the first ENI of the node was
//     created in, to avoid putting the ENI in a surprising subnet if possible.
//  3. If none of these work, fall back to just choosing the subnet with the most addresses
//     available.
func (n *Node) findSuitableSubnet(spec eniTypes.Spec, limits ipamTypes.Limits) *ipamTypes.Subnet {
	var subnet *ipamTypes.Subnet
	ids := []string{spec.SubnetID}
	log.Infof("@@@@@@@@@@@@@@@@@@ subnet id is %s", spec.SubnetID)
	if len(spec.SubnetID) > 0 {
		return n.manager.FindSubnetByIDs(spec.VPCID, spec.AvailabilityZone, ids)
	}

	subnet = n.manager.GetSubnet(spec.SubnetID)
	return subnet
}

// allocENIIndex will alloc an monotonically increased index for each ENI on this instance.
// The index generated the first time this ENI is created, and stored in ENI.Tags.
func (n *Node) allocENIIndex() (int, error) {
	// alloc index for each created ENI
	used := make([]bool, maxENIPerNode)
	for _, v := range n.enis {
		index := utils.GetENIIndexFromTags(v.Tags)
		if index > maxENIPerNode || index < 0 {
			return 0, fmt.Errorf("ENI index(%d) is out of range", index)
		}
		used[index] = true
	}
	// ECS has at least 1 ENI, 0 is reserved for eth0
	i := 1
	for ; i < maxENIPerNode; i++ {
		if !used[i] {
			break
		}
	}
	return i, nil
}