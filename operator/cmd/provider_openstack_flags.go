// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_openstack

package cmd

import (
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	flags := rootCmd.Flags()

	flags.String(operatorOption.OpenStackProjectID, "", "Specific project ID for OpenStack.")
	option.BindEnv(Vp, operatorOption.OpenStackProjectID)
	flags.Bool(operatorOption.OpenStackReleaseExcessIPs, true, "Enable releasing excess free IP addresses from OpenStack.")
	option.BindEnv(Vp, operatorOption.OpenStackReleaseExcessIPs)
	flags.String(operatorOption.OpenStackDefaultSubnetID, "", "Specific subnet ID for OpenStack to create default pool")
	option.BindEnv(Vp, operatorOption.OpenStackDefaultSubnetID)
	flags.String(operatorOption.OpenStackSecurityGroupIDs, "", "Specific security groups for OpenStack pools")
	option.BindEnv(Vp, operatorOption.OpenStackSecurityGroupIDs)
	flags.Int(operatorOption.OpenStackHttpTimeout, 60, "OpenStack client http timeout")
	option.BindEnv(Vp, operatorOption.OpenStackHttpTimeout)
	flags.Int(operatorOption.OpenStackGateWayIndex, -2, "use index of subnet cidr address as gateway")
	option.BindEnv(Vp, operatorOption.OpenStackGateWayIndex)
	flags.Int(operatorOption.OpenStackMaxNics, 6, "Max number of nics on one vm")
	option.BindEnv(Vp, operatorOption.OpenStackMaxNics)
	flags.Int(operatorOption.OpenStackMaxV4PodIPs, 100, "Max number of ipv4 pod ips on one vm nic")
	option.BindEnv(Vp, operatorOption.OpenStackMaxV4PodIPs)
	flags.Int(operatorOption.OpenStackMaxV6PodIPs, 100, "Max number of ipv6 pod ips on one vm nic")
	option.BindEnv(Vp, operatorOption.OpenStackMaxV6PodIPs)
	flags.Int(operatorOption.OpenstackDefaultCreatePortsStep, 20, "The step every create in bulk per pool")
	option.BindEnv(Vp, operatorOption.OpenstackDefaultCreatePortsStep)
	flags.Int(operatorOption.OpenstackDefaultCreatePortsInterval, 60, "The interval between each creation")
	option.BindEnv(Vp, operatorOption.OpenstackDefaultCreatePortsInterval)

	Vp.BindPFlags(flags)
}
