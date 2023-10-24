// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"errors"
	"fmt"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/attachinterfaces"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/attributestags"
	"github.com/gophercloud/gophercloud/pagination"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	eniTypes "github.com/cilium/cilium/pkg/openstack/eni/types"
	"github.com/cilium/cilium/pkg/openstack/types"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"

	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/pkg/api/helpers"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-openstack-operator")

const (
	NetworkID = "network_id"
	SubnetID  = "subnet_id"
	ProjectID = "project_id"

	VMInterfaceName  = "cilium-vm-port"
	PodInterfaceName = "cilium-pod-port"

	VMDeviceOwner  = "compute:"
	PodDeviceOwner = "network:secondary"
	CharSet        = "abcdefghijklmnopqrstuvwxyz0123456789"

	FakeAddresses = 100
)

const (
	PortNotFoundErr = "port not found"
	IfaceLimitErr   = "reaches the eni upper limit"
)

var maxAttachRetries = wait.Backoff{
	Duration: 2500 * time.Millisecond,
	Factor:   1,
	Jitter:   0.1,
	Steps:    6,
	Cap:      0,
}

// Client an OpenStack API client
type Client struct {
	neutronV2  *gophercloud.ServiceClient
	novaV2     *gophercloud.ServiceClient
	keystoneV3 *gophercloud.ServiceClient

	limiter    *helpers.APILimiter
	metricsAPI MetricsAPI
	filters    map[string]string
}

// PortCreateOpts options to create port
type PortCreateOpts struct {
	Name          string
	NetworkID     string
	SubnetID      string
	IPAddress     string
	ProjectID     string
	SecurityGroup []string
	DeviceID      string
	DeviceOwner   string
	Tags          string
}

type FixedIPOpt struct {
	SubnetID        string `json:"subnet_id,omitempty"`
	IPAddress       string `json:"ip_address,omitempty"`
	IPAddressSubstr string `json:"ip_address_subdir,omitempty"`
}
type FixedIPOpts []FixedIPOpt

// MetricsAPI represents the metrics maintained by the OpenStack API client
type MetricsAPI interface {
	helpers.MetricsAPI
	ObserveAPICall(call, status string, duration float64)
}

// NewClient create the client
func NewClient(metrics MetricsAPI, rateLimit float64, burst int, filters map[string]string) (*Client, error) {
	provider, err := newProviderClientOrDie(false)
	if err != nil {
		return nil, err
	}
	domainTokenProvider, err := newProviderClientOrDie(true)
	if err != nil {
		return nil, err
	}

	netV2, err := newNetworkV2ClientOrDie(provider)
	if err != nil {
		return nil, err
	}

	computeV2, err := newComputeV2ClientOrDie(provider)
	if err != nil {
		return nil, err
	}

	idenV3, err := newIdentityV3ClientOrDie(domainTokenProvider)
	if err != nil {
		return nil, err
	}

	log.Errorf("######## client details is: %+v", idenV3)
	return &Client{
		neutronV2:  netV2,
		novaV2:     computeV2,
		keystoneV3: idenV3,
		limiter:    helpers.NewAPILimiter(metrics, rateLimit, burst),
		metricsAPI: metrics,
		filters:    filters,
	}, nil
}

func newProviderClientOrDie(domainScope bool) (*gophercloud.ProviderClient, error) {
	opt, err := openstack.AuthOptionsFromEnv()
	if err != nil {
		return nil, err
	}
	// with OS_PROJECT_NAME in env, AuthOptionsFromEnv return project scope token
	// which can not list projects, we need a domain scope token here
	if domainScope {
		opt.TenantName = ""
		opt.Scope = &gophercloud.AuthScope{
			DomainName: os.Getenv("OS_DOMAIN_NAME"),
		}
	}
	p, err := openstack.AuthenticatedClient(opt)
	if err != nil {
		return nil, err
	}
	p.HTTPClient = http.Client{
		Transport: http.DefaultTransport,
		Timeout:   time.Second * 60,
	}
	p.ReauthFunc = func() error {
		newprov, err := openstack.AuthenticatedClient(opt)
		if err != nil {
			return err
		}
		p.CopyTokenFrom(newprov)
		return nil
	}
	return p, nil
}

func newNetworkV2ClientOrDie(p *gophercloud.ProviderClient) (*gophercloud.ServiceClient, error) {
	client, err := openstack.NewNetworkV2(p, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}
	return client, nil
}

// Create a ComputeV2 service client using the AKSK provider
func newComputeV2ClientOrDie(p *gophercloud.ProviderClient) (*gophercloud.ServiceClient, error) {
	client, err := openstack.NewComputeV2(p, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}
	return client, nil
}

func newIdentityV3ClientOrDie(p *gophercloud.ProviderClient) (*gophercloud.ServiceClient, error) {
	client, err := openstack.NewIdentityV3(p, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}
	return client, nil
}

// GetInstances returns the list of all instances including their ENIs as
// instanceMap
func (c *Client) GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceIDs []string) (*ipamTypes.InstanceMap, error) {
	instances := ipamTypes.NewInstanceMap()
	log.Errorf("######## Do Get instances")
	var networkInterfaces []ports.Port
	var err error

	networkInterfaces, err = c.describeNetworkInterfaces(instanceIDs)
	if err != nil {
		return nil, err
	}

	for _, iface := range networkInterfaces {
		if !strings.HasPrefix(iface.DeviceOwner, VMDeviceOwner) {
			continue
		}
		log.Errorf("######## networkInterface is %+v", iface)
		id, eni, err := parseENI(&iface, subnets)
		if err != nil {
			log.Errorf("######## Failed to pares eni %+v, with error %s", iface, err)
			continue
		}

		log.Errorf("######## Update instancesMap, instanceID is %s, eni is: %+v", id, eni)
		if id != "" {
			instances.Update(id, ipamTypes.InterfaceRevision{Resource: eni})
		}
	}

	return instances, nil
}

func (c *Client) GetInstance(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceID string) (instance *ipamTypes.Instance, err error) {
	log.Errorf("######## Do Get instance, id is %s", instanceID)

	instance = &ipamTypes.Instance{}
	instance.Interfaces = map[string]ipamTypes.InterfaceRevision{}
	var networkInterfaces []ports.Port

	networkInterfaces, err = c.describeNetworkInterfacesByInstance(instanceID)
	if err != nil {
		return instance, err
	}

	for _, iface := range networkInterfaces {
		if !strings.HasPrefix(iface.DeviceOwner, VMDeviceOwner) {
			continue
		}
		log.Errorf("######## networkInterface is %+v", iface)
		ifId, eni, err := parseENI(&iface, subnets)
		if err != nil {
			log.Errorf("######## Failed to pares eni %+v, with error %s", iface, err)
			continue
		}

		instance.Interfaces[ifId] = ipamTypes.InterfaceRevision{
			Resource: eni,
		}
	}
	log.Errorf("######## Update instances, instanceID is %s, iface is: %+v", instanceID, instance.Interfaces)

	return
}

// GetVpcs retrieves and returns all Vpcs
func (c *Client) GetVpcs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error) {
	vpcs := ipamTypes.VirtualNetworkMap{}
	log.Errorf("######## Do Get vpcs")
	vpcList, err := c.describeVpcs()
	if err != nil {
		return nil, err
	}

	for _, v := range vpcList {
		vpc := &ipamTypes.VirtualNetwork{ID: v.ID}
		vpcs[vpc.ID] = vpc
	}

	return vpcs, nil
}

// GetSubnets returns all subnets as a subnetMap
func (c *Client) GetSubnets(ctx context.Context) (ipamTypes.SubnetMap, error) {
	subnets := ipamTypes.SubnetMap{}
	log.Errorf("######## Do Get subnets")
	subnetList, err := c.describeSubnets()
	if err != nil {
		return nil, err
	}

	for _, s := range subnetList {
		c, err := cidr.ParseCIDR(s.CIDR)
		if err != nil {
			continue
		}

		subnet := &ipamTypes.Subnet{
			ID:                 s.ID,
			VirtualNetworkID:   s.NetworkID,
			CIDR:               c,
			AvailableAddresses: FakeAddresses,
		}

		subnets[subnet.ID] = subnet
	}

	return subnets, nil
}

// GetSecurityGroups returns all security groups as a SecurityGroupMap
func (c *Client) GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error) {
	securityGroups := types.SecurityGroupMap{}
	log.Errorf("######## Do Get sgs")
	secGroupList, err := c.describeSecurityGroups()
	if err != nil {
		return securityGroups, err
	}

	for _, sg := range secGroupList {
		id := sg.ID

		securityGroup := &types.SecurityGroup{
			ID: id,
		}

		securityGroups[id] = securityGroup
	}

	return securityGroups, nil
}

// CreateNetworkInterface creates an ENI with the given parameters
func (c *Client) CreateNetworkInterface(ctx context.Context, subnetID, netID, instanceID string, groups []string, pool ipam.Pool, maxENICount int) (string, *eniTypes.ENI, error) {
	log.Errorf("######## Do create interface subnetid is: %s, networkid is: %s", subnetID, netID)

	ifaces, err := c.describeNetworkInterfacesByInstance(instanceID)
	if len(ifaces) >= maxENICount {
		return "", nil, errors.New(IfaceLimitErr)
	}

	opt := PortCreateOpts{
		Name:        fmt.Sprintf(VMInterfaceName+"-%s-%s", pool, randomString(10)),
		NetworkID:   netID,
		SubnetID:    subnetID,
		DeviceOwner: fmt.Sprintf(VMDeviceOwner+"%s", instanceID),
		ProjectID:   c.filters[ProjectID],
	}
	eni, err := c.createPort(opt)
	if err != nil {
		return "", nil, err
	}

	return eni.ID, eni, nil
}

// DeleteNetworkInterface deletes an ENI with the specified ID
func (c *Client) DeleteNetworkInterface(ctx context.Context, eniID string) error {
	r := ports.Delete(c.neutronV2, eniID)
	return r.ExtractErr()
}

// ListNetworkInterface list all interfaces with the specified instanceID
func (c *Client) ListNetworkInterface(ctx context.Context, instanceID string) ([]attachinterfaces.Interface, error) {
	var err error
	var result []attachinterfaces.Interface
	err = attachinterfaces.List(c.neutronV2, instanceID).EachPage(
		func(page pagination.Page) (bool, error) {
			result, err = attachinterfaces.ExtractInterfaces(page)
			if err != nil {
				return false, err
			}
			return true, nil
		})
	return result, err
}

// AttachNetworkInterface attaches a previously created ENI to an instance
func (c *Client) AttachNetworkInterface(ctx context.Context, instanceID, eniID string) error {
	log.Errorf("######## Do attach network interface #######")

	createOpts := attachinterfaces.CreateOpts{
		PortID: eniID,
	}
	_, err := attachinterfaces.Create(c.novaV2, instanceID, createOpts).Extract()
	if err != nil {
		return err
	}

	return nil
}

// DetachNetworkInterface to detach a previously created ENI from an instance
func (c *Client) DetachNetworkInterface(ctx context.Context, instanceID, eniID string) error {
	log.Errorf("######## Do detach network interface #######")
	return attachinterfaces.Delete(c.novaV2, instanceID, eniID).ExtractErr()
}

// AssignPrivateIPAddresses assigns the specified number of secondary IP
// return allocated IPs
func (c *Client) AssignPrivateIPAddresses(ctx context.Context, eniID string, toAllocate int) ([]string, error) {
	log.Errorf("######## Do Assign ip addresses for nic %s, count is %d", eniID, toAllocate)

	port, err := c.getPort(eniID)
	if err != nil {
		log.Errorf("######## Failed to get port: %s, with error %s", eniID, err)
		return nil, err
	}

	var addresses []string
	for i := 0; i < toAllocate; i++ {
		opt := PortCreateOpts{
			Name:        fmt.Sprintf(PodInterfaceName+"-%s", randomString(10)),
			NetworkID:   port.NetworkID,
			SubnetID:    port.FixedIPs[0].SubnetID,
			DeviceOwner: PodDeviceOwner,
			DeviceID:    eniID,
			ProjectID:   c.filters[ProjectID],
		}
		p, err := c.createPort(opt)
		if err != nil {
			log.Errorf("######## Failed to create port with error %s", err)
			return addresses, err
		}

		err = c.addPortAllowedAddressPairs(eniID, []ports.AddressPair{
			{
				IPAddress:  p.IP,
				MACAddress: port.MACAddress,
			},
		})
		if err != nil {
			log.Errorf("######## Failed to update port allowed-address-pairs with error: %+v", err)
			err = c.deletePort(p.ID)
			if err != nil {
				log.Errorf("######## Failed to rollback to delete port with error: %+v", err)
			}
			return addresses, err
		}
		addresses = append(addresses, p.IP)
	}

	return addresses, nil
}

// UnassignPrivateIPAddresses unassign specified IP addresses from ENI
// should not provide Primary IP
func (c *Client) UnassignPrivateIPAddresses(ctx context.Context, eniID string, addresses []string) (isEmpty bool, err error) {
	log.Errorf("Do Unassign ip addresses for nic %s, addresses to release is %s", eniID, addresses)

	port, err := c.getPort(eniID)
	if err != nil {
		log.Errorf("######## Failed to get port: %s, with error %s", eniID, err)
		return false, err
	}

	networkId := port.NetworkID
	var allowedAddressPairs []ports.AddressPair
	var releasedIP []string

	for _, pair := range port.AllowedAddressPairs {
		release := false
		for _, ip := range addresses {
			if pair.IPAddress == ip {
				release = true
				releasedIP = append(releasedIP, ip)
				break
			}
		}
		if release {
			allowedAddressPairs = append(allowedAddressPairs, pair)
		}
	}

	if len(releasedIP) != len(addresses) {
		log.Errorf("########### Not mach, expected is %s, actual is %s", addresses, releasedIP)
	}

	log.Errorf("########### origin pairs is %s, new pairs is %s, expected is %s, actual is %s", port.AllowedAddressPairs, allowedAddressPairs, addresses, releasedIP)

	err = c.deletePortAllowedAddressPairs(eniID, allowedAddressPairs)
	if err != nil {
		log.Errorf("######## Failed to update port allowed-address-pairs with error: %+v", err)
		if err != nil {
			log.Errorf("######## Failed to rollback to delete port with error: %+v", err)
		}
		return false, err
	}

	for _, ip := range releasedIP {
		port, err = c.getPortFromIP(networkId, ip)
		if err != nil {
			log.Errorf("######## Failed to get port: with ip %s, with error %s", ip, err)
		}
		log.Errorf("######## port: with ip %s result is: %+v", ip, port)
		err = c.deletePort(port.ID)
		if err != nil {
			log.Errorf("######## Failed to delete port %s with error: %+v", port.ID, err)
		}
	}
	port, err = c.getPort(eniID)
	if err != nil {
		return false, err
	}
	if len(port.AllowedAddressPairs) == 0 {
		return true, nil
	}

	return false, nil
}

// updatePortAllowedAddressPairs to assign secondary ip address
func (c Client) updatePortAllowedAddressPairs(eniID string, pairs []ports.AddressPair) error {
	opts := ports.UpdateOpts{
		AllowedAddressPairs: &pairs,
	}
	port, err := ports.Update(c.neutronV2, eniID, opts).Extract()
	if err != nil {
		return err
	}
	log.Errorf("######## port updated is: %+v", port)
	return nil
}

// addPortAllowedAddressPairs to assign secondary ip address
func (c Client) addPortAllowedAddressPairs(eniID string, pairs []ports.AddressPair) error {
	opts := ports.UpdateOpts{
		AllowedAddressPairs: &pairs,
	}
	port, err := ports.AddAllowedAddressPair(c.neutronV2, eniID, opts).Extract()
	if err != nil {
		return err
	}
	log.Errorf("######## port updated is: %+v", port)
	return nil
}

// deletePortAllowedAddressPairs to assign secondary ip address
func (c Client) deletePortAllowedAddressPairs(eniID string, pairs []ports.AddressPair) error {
	if len(pairs) == 0 {
		return nil
	}
	opts := ports.UpdateOpts{
		AllowedAddressPairs: &pairs,
	}
	port, err := ports.RemoveAllowedAddressPair(c.neutronV2, eniID, opts).Extract()
	if err != nil {
		return err
	}
	log.Errorf("######## port updated is: %+v", port)
	return nil
}

// AddTagToNetworkInterface add tag to port
func (c Client) AddTagToNetworkInterface(ctx context.Context, eniID string, tags string) error {
	return attributestags.Add(c.neutronV2, "ports", eniID, tags).ExtractErr()
}

// get neutron port
func (c Client) getPort(id string) (*ports.Port, error) {
	return ports.Get(c.neutronV2, id).Extract()
}

// get neutron port with subnetID and ip address
func (c Client) getPortFromIP(netID, ip string) (*ports.Port, error) {
	var result []ports.Port
	var err error

	opts := ports.ListOpts{
		NetworkID: netID,
		FixedIPs: []ports.FixedIPOpts{
			ports.FixedIPOpts{
				IPAddress: ip,
			},
		},
	}

	err = ports.List(c.neutronV2, opts).EachPage(func(page pagination.Page) (bool, error) {
		result, err = ports.ExtractPorts(page)
		if err != nil {
			return false, err
		}
		return true, nil
	})

	if err == nil && len(result) != 1 {
		log.Errorf("######## port: with ip %s result is unexpected: %+v", ip, result)
		return nil, errors.New(PortNotFoundErr)
	}

	if len(result) != 1 {
		log.Errorf("######## port: with ip %s result is unexpected: %+v", ip, result)
		return nil, fmt.Errorf("failed to get secondary ip")
	}

	return &result[0], nil
}

// create neturon port for both CreateNetworkInterface and AssignIpAddress
func (c *Client) createPort(opt PortCreateOpts) (*eniTypes.ENI, error) {

	copts := ports.CreateOpts{
		Name:        opt.Name,
		NetworkID:   opt.NetworkID,
		DeviceOwner: opt.DeviceOwner,
		DeviceID:    opt.DeviceID,
		ProjectID:   opt.ProjectID,
		FixedIPs: FixedIPOpts{
			{
				SubnetID:  opt.SubnetID,
				IPAddress: opt.IPAddress,
			},
		},
	}

	port, err := ports.Create(c.neutronV2, copts).Extract()
	if err != nil {
		return nil, err
	}

	eni := eniTypes.ENI{
		ID:             port.ID,
		IP:             port.FixedIPs[0].IPAddress,
		MAC:            port.MACAddress,
		SecurityGroups: port.SecurityGroups,
		VPC:            eniTypes.VPC{ID: port.NetworkID},
		Subnet:         eniTypes.Subnet{ID: opt.SubnetID},
	}

	return &eni, nil
}

func (c *Client) deletePort(id string) error {
	r := ports.Delete(c.neutronV2, id)
	return r.ExtractErr()
}

// parseENI parses a ecs.NetworkInterface as returned by the ecs service API,
// converts it into a eniTypes.ENI object
func parseENI(port *ports.Port, subnets ipamTypes.SubnetMap) (instanceID string, eni *eniTypes.ENI, err error) {

	if len(port.FixedIPs) == 0 {
		log.Errorf("##### Failed to parse ENI %+v, because that fixedIPs is empty.", port)
		return "", nil, fmt.Errorf("FixedIPs of port is empty")
	}

	var eniType string
	if strings.HasPrefix(port.DeviceOwner, VMDeviceOwner) {
		eniType = eniTypes.ENITypePrimary
	} else if strings.HasPrefix(port.DeviceOwner, PodDeviceOwner) {
		eniType = eniTypes.ENITypeSecondary
	}

	subnetID := port.FixedIPs[0].SubnetID
	eni = &eniTypes.ENI{
		ID:             port.ID,
		IP:             port.FixedIPs[0].IPAddress,
		MAC:            port.MACAddress,
		SecurityGroups: port.SecurityGroups,
		VPC:            eniTypes.VPC{ID: port.NetworkID},
		Subnet:         eniTypes.Subnet{ID: subnetID},
		Type:           eniType,
		Tags:           port.Tags,
	}

	if name, found := strings.CutPrefix(port.Name, "cilium-vm-port-"); found {
		index := strings.LastIndex(name, "-")
		if index > 0 {
			eni.Pool = name[:index]
		} else {
			log.Errorf("ENI's pool can not found on name %s", port.Name)
		}
	}

	subnet, ok := subnets[subnetID]
	if ok && subnet.CIDR != nil {
		eni.Subnet.CIDR = subnet.CIDR.String()
	}

	var ipsets []eniTypes.PrivateIPSet
	for _, pairs := range port.AllowedAddressPairs {
		if validIPAddress(pairs.IPAddress, subnet.CIDR.IPNet) {
			ipsets = append(ipsets, eniTypes.PrivateIPSet{
				IpAddress: pairs.IPAddress,
			})
		}
	}
	eni.SecondaryIPSets = ipsets

	return port.DeviceID, eni, nil
}

func validIPAddress(ipStr string, cidr *net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip != nil {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// describeNetworkInterfacesByInstance lists all ENIs by instance
func (c *Client) describeNetworkInterfacesByInstance(instanceID string) ([]ports.Port, error) {
	var result []ports.Port
	var err error

	opts := ports.ListOpts{
		ProjectID: c.filters[ProjectID],
		DeviceID:  instanceID,
	}

	err = ports.List(c.neutronV2, opts).EachPage(func(page pagination.Page) (bool, error) {
		result, err = ports.ExtractPorts(page)
		if err != nil {
			return false, err
		}

		return true, nil
	})

	return result, nil
}

// describeNetworkInterfaces lists all ENIs
func (c *Client) describeNetworkInterfaces(instances []string) ([]ports.Port, error) {
	var result []ports.Port
	var err error

	for _, instance := range instances {
		opts := ports.ListOpts{
			ProjectID: c.filters[ProjectID],
			DeviceID:  instance,
		}

		err = ports.List(c.neutronV2, opts).EachPage(func(page pagination.Page) (bool, error) {
			result, err = ports.ExtractPorts(page)
			if err != nil {
				return false, err
			}

			return true, nil
		})
	}

	return result, err
}

// describeVpcs lists all VPCs
func (c *Client) describeVpcs() ([]networks.Network, error) {
	opts := networks.ListOpts{
		ProjectID: c.filters[ProjectID],
	}

	pages, err := networks.List(c.neutronV2, opts).AllPages()
	if err != nil {
		return nil, err
	}
	allNetworks, _ := networks.ExtractNetworks(pages)
	return allNetworks, nil
}

// describeSubnets lists all subnets
func (c *Client) describeSubnets() ([]subnets.Subnet, error) {
	opts := subnets.ListOpts{
		ProjectID: c.filters[ProjectID],
	}
	pages, err := subnets.List(c.neutronV2, opts).AllPages()
	if err != nil {
		return nil, err
	}
	allSubnets, _ := subnets.ExtractSubnets(pages)
	return allSubnets, nil
}

func (c *Client) describeSecurityGroups() ([]groups.SecGroup, error) {
	opts := groups.ListOpts{
		ProjectID: c.filters[ProjectID],
	}
	pages, err := groups.List(c.neutronV2, opts).AllPages()
	if err != nil {
		return nil, err
	}
	allSecGroups, _ := groups.ExtractGroups(pages)
	return allSecGroups, nil
}

func randomString(length int) string {
	rand.Seed(time.Now().UnixNano())

	b := make([]byte, length)
	for i := range b {
		b[i] = CharSet[rand.Intn(len(CharSet))]
	}
	return string(b)
}

func (c *Client) UnassignPrivateIPAddressesRetainPort(ctx context.Context, eniID string, address []string) error {
	log.Errorf("##### Do Unassign static ip addresses for nic %s, addresses to release is %s", eniID, address)

	if len(address) != 1 {
		return errors.New("no ip address need to be released")
	}

	port, err := c.getPort(eniID)
	if err != nil {
		log.Errorf("failed to get port: %s, with error %s", eniID, err)
		return err
	}

	idx := -1

	for i, pair := range port.AllowedAddressPairs {
		if pair.IPAddress == address[0] {
			idx = i
			break
		}
	}

	if idx == -1 {
		return errors.New(fmt.Sprintf("no address found attached in eni %v", eniID))
	}

	err = c.deletePortAllowedAddressPairs(eniID, []ports.AddressPair{
		{
			IPAddress:  address[0],
			MACAddress: port.MACAddress,
		},
	})
	if err != nil {
		log.Errorf("failed to update port allowed-address-pairs with error: %v", err)
		return err
	}

	return nil
}

func (c *Client) AssignStaticPrivateIPAddresses(ctx context.Context, eniID string, address string) error {
	log.Errorf("######## Do Assign static ip addresses for nic %s", eniID)

	port, err := c.getPort(eniID)
	if err != nil {
		log.Errorf("######## Failed to get port: %s, with error %s", eniID, err)
		return err
	}

	p, err := c.getPortFromIP(port.NetworkID, address)
	if p == nil {
		_, err = c.createPort(PortCreateOpts{
			Name:        fmt.Sprintf(PodInterfaceName+"-%s", randomString(10)),
			NetworkID:   port.NetworkID,
			IPAddress:   address,
			SubnetID:    port.FixedIPs[0].SubnetID,
			DeviceOwner: PodDeviceOwner,
			DeviceID:    eniID,
			ProjectID:   c.filters[ProjectID],
		})
		if err != nil {
			log.Infof("Back to create static ip port failed: %v", err)
			return err
		}
		log.Infof("Back to create static ip port: %v success", address)
	} else {
		opts := ports.UpdateOpts{
			DeviceID: &eniID,
		}
		_, err = ports.Update(c.neutronV2, p.ID, opts).Extract()
		if err != nil {
			return err
		}
		log.Infof("Update port for static ip %s success", address)
	}

	if err != nil {
		log.Errorf("######## Failed to get port with error %s", err)
		return err
	}

	for _, pair := range port.AllowedAddressPairs {
		if pair.IPAddress == address {
			return nil
		}
	}
	err = c.addPortAllowedAddressPairs(eniID, []ports.AddressPair{
		{
			IPAddress:  address,
			MACAddress: port.MACAddress,
		},
	})
	if err != nil {
		log.Errorf("######## Failed to update port allowed-address-pairs with error: %+v", err)
		return err
	}

	return nil
}

func (c *Client) DeleteNeutronPort(address string, networkID string) error {
	port, err := c.getPortFromIP(networkID, address)
	if err != nil {
		if err.Error() == PortNotFoundErr {
			return nil
		}
		return err
	}
	return c.deletePort(port.ID)
}
