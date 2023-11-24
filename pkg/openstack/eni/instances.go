// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	eniTypes "github.com/cilium/cilium/pkg/openstack/eni/types"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/attachinterfaces"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/openstack/types"
)

// OpenStackAPI is the API surface used of the ECS API
type OpenStackAPI interface {
	GetInstances(ctx context.Context, subnets ipamTypes.SubnetMap, azs []string) (*ipamTypes.InstanceMap, error)
	GetSubnets(ctx context.Context) (ipamTypes.SubnetMap, error)
	GetInstance(ctx context.Context, subnets ipamTypes.SubnetMap, instanceId string) (*ipamTypes.Instance, error)
	GetVpcs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error)
	GetAzs(ctx context.Context) ([]string, error)
	GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error)
	CreateNetworkInterface(ctx context.Context, subnetID, netID, instanceID string, groups []string, pool string) (string, *eniTypes.ENI, error)
	DeleteNetworkInterface(ctx context.Context, eniID string) error
	AttachNetworkInterface(ctx context.Context, instanceID, eniID string) error
	DetachNetworkInterface(ctx context.Context, instanceID, eniID string) error
	AssignPrivateIPAddresses(ctx context.Context, eniID string, toAllocate int, pool string) ([]string, error)
	UnassignPrivateIPAddresses(ctx context.Context, eniID string, addresses []string, pool string) (err error)
	AddTagToNetworkInterface(ctx context.Context, eniID string, tags string) error
	UnassignPrivateIPAddressesRetainPort(ctx context.Context, subNetID string, address string) error
	AssignStaticPrivateIPAddresses(ctx context.Context, eniID string, address string, portId string) (string, error)
	DeleteNeutronPort(address string, networkID string, portId string, pool string) error
	ListNetworkInterface(ctx context.Context, instanceID string) ([]attachinterfaces.Interface, error)
	RefreshAvailablePool()
}

// InstancesManager maintains the list of instances. It must be kept up to date
// by calling resync() regularly.
type InstancesManager struct {
	mutex          lock.RWMutex
	resyncLock     lock.RWMutex
	instances      *ipamTypes.InstanceMap
	subnets        ipamTypes.SubnetMap
	vpcs           ipamTypes.VirtualNetworkMap
	securityGroups types.SecurityGroupMap
	api            OpenStackAPI
	excludeIPs     map[string]struct{}
}

// NewInstancesManager returns a new instances manager
func NewInstancesManager(api OpenStackAPI) *InstancesManager {
	return &InstancesManager{
		instances:  ipamTypes.NewInstanceMap(),
		api:        api,
		excludeIPs: map[string]struct{}{},
	}
}

// CreateNode is called on discovery of a new node and returns the ENI node
// allocation implementation for the new node
func (m *InstancesManager) CreateNode(obj *v2.CiliumNode, node *ipam.Node) ipam.NodeOperations {
	return &Node{k8sObj: obj, manager: m, node: node, instanceID: obj.InstanceID()}
}

// HasInstance returns whether the instance is in instances
func (m *InstancesManager) HasInstance(instanceID string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.instances.Exists(instanceID)
}

// GetPoolQuota returns the number of available IPs in all IP pools
func (m *InstancesManager) GetPoolQuota() ipamTypes.PoolQuotaMap {
	pool := ipamTypes.PoolQuotaMap{}
	for subnetID, subnet := range m.GetSubnets(context.TODO()) {
		pool[ipamTypes.PoolID(subnetID)] = ipamTypes.PoolQuota{
			AvailabilityZone: subnet.AvailabilityZone,
			AvailableIPs:     subnet.AvailableAddresses,
		}
	}
	return pool
}

// Resync fetches the list of ECS instances and subnets and updates the local
// cache in the instanceManager. It returns the time when the resync has
// started or time.Time{} if it did not complete.
func (m *InstancesManager) Resync(ctx context.Context) time.Time {
	// Full API resync should block the instance incremental resync from all nodes.
	m.resyncLock.Lock()
	defer m.resyncLock.Unlock()
	// An empty instanceID indicates the full resync.
	return m.resync(ctx, "", true)
}

// GetSubnet returns the subnet by subnet ID
//
// The returned subnet is immutable so it can be safely accessed
func (m *InstancesManager) GetSubnet(subnetID string) *ipamTypes.Subnet {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.subnets[subnetID]
}

// GetSubnets returns all the tracked subnets
//
// The returned subnetMap is immutable so it can be safely accessed
func (m *InstancesManager) GetSubnets(ctx context.Context) ipamTypes.SubnetMap {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	subnetsCopy := make(ipamTypes.SubnetMap)
	for k, v := range m.subnets {
		subnetsCopy[k] = v
	}

	return subnetsCopy
}

// ForeachInstance will iterate over each instance inside `instances`, and call
// `fn`. This function is read-locked for the entire execution.
func (m *InstancesManager) ForeachInstance(instanceID string, fn ipamTypes.InterfaceIterator) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	m.instances.ForeachInterface(instanceID, fn)
}

// UpdateENI updates the ENI definition of an ENI for a particular instance. If
// the ENI is already known, the definition is updated, otherwise the ENI is
// added to the instance.
func (m *InstancesManager) UpdateENI(instanceID string, eni *eniTypes.ENI) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	eniRevision := ipamTypes.InterfaceRevision{Resource: eni}
	m.instances.Update(instanceID, eniRevision)
}

// FindSubnetByIDs returns the subnet within a provided list of vSwitch IDs with the fewest available addresses,
// matching vpc and az.
func (m *InstancesManager) FindSubnetByIDs(vpcID, availabilityZone string, subnetIDs []string) *ipamTypes.Subnet {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var bestSubnet *ipamTypes.Subnet
	for _, s := range m.subnets {
		if s.VirtualNetworkID == vpcID {
			for _, subnetID := range subnetIDs {
				if s.ID == subnetID {
					if bestSubnet == nil || bestSubnet.AvailableAddresses < s.AvailableAddresses {
						bestSubnet = s
					}
					continue
				}
			}
		}
	}
	return bestSubnet
}

// DeleteInstance delete instance from m.instances
func (m *InstancesManager) DeleteInstance(instanceID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.instances.Delete(instanceID)
}

func (m *InstancesManager) ExcludeIP(ip string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.excludeIPs[ip] = struct{}{}
}

func (m *InstancesManager) IncludeIP(ip string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.excludeIPs, ip)
}

func (m *InstancesManager) InstanceSync(ctx context.Context, instanceID string) time.Time {
	// Instance incremental resync from different nodes should be executed in parallel,
	// but must block the full API resync.
	m.resyncLock.RLock()
	defer m.resyncLock.RUnlock()
	return m.resync(ctx, instanceID, false)
}

func (m *InstancesManager) resync(ctx context.Context, instanceID string, fullSync bool) time.Time {
	resyncStart := time.Now()

	var subnets ipamTypes.SubnetMap

	// An empty instanceID indicates that this is full resync, ENIs from all instances
	// will be refetched from EC2 API and updated to the local cache. Otherwise only
	// the given instance will be updated.
	if fullSync {
		azs, err := m.api.GetAzs(ctx)
		if err != nil {
			log.WithError(err).Warning("Unable to synchronize AZ list")
			return time.Time{}
		}

		log.Debugf("##### az list is %+v", azs)

		subnets, err = m.api.GetSubnets(ctx)
		if err != nil {
			log.WithError(err).Warning("Unable to retrieve VPC vSwitches list")
			return time.Time{}
		}
		m.api.RefreshAvailablePool()
		instances, err := m.api.GetInstances(ctx, subnets, azs)
		if err != nil {
			log.WithError(err).Warning("Unable to synchronize ECS interface list")
			return time.Time{}
		}

		log.WithFields(logrus.Fields{
			"numInstances": instances.NumInstances(),
			"numSubnets":   len(subnets),
		}).Info("Synchronized OpenStack ENI information")

		m.mutex.Lock()
		defer m.mutex.Unlock()
		m.instances = instances
	} else {
		instance, err := m.api.GetInstance(ctx, m.subnets, instanceID)
		if err != nil {
			log.WithError(err).Warning("Unable to synchronize openstack interface list")
			return time.Time{}
		}

		log.WithFields(logrus.Fields{
			"instance":   instanceID,
			"numSubnets": len(subnets),
		}).Infof("Synchronized ENI information for the corresponding instance %d", instanceID)

		m.mutex.Lock()
		defer m.mutex.Unlock()
		m.instances.UpdateInstance(instanceID, instance)
	}

	if subnets != nil {

		m.subnets = subnets
		ipam.SyncPoolToAPIServer(subnets)
	}

	return resyncStart
}
