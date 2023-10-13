// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"github.com/vishvananda/netlink"
	"net"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	eniTypes "github.com/cilium/cilium/pkg/openstack/eni/types"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func configureOpenStackENIs(oldNode, newNode *ciliumv2.CiliumNode, mtuConfig MtuConfiguration) error {
	if oldNode != nil && oldNode.Status.OpenStack.ENIs != nil && newNode.Status.OpenStack.ENIs != nil {
		log.Errorf("############ configure openstack enis: oldNode is %+v, newNode is %+v", oldNode.Status.OpenStack.ENIs, newNode.Status.OpenStack.ENIs)
	}
	var (
		existingENIByName map[string]eniTypes.ENI
		addedENIByMac     = configMap{}
	)

	if oldNode != nil {
		existingENIByName = oldNode.Status.OpenStack.ENIs
	}

	for id, eni := range newNode.Status.OpenStack.ENIs {
		log.Errorf("############ eni from newNode is %+v", eni)

		//(fixme) judge to skip primary interface if eni has no pool attribute
		//instead of utils.IsExcludedByTags(eni.Tags) as workaround for #EAS-119284
		if len(eni.Pool) == 0 {
			continue
		}

		if _, ok := existingENIByName[id]; !ok {
			log.Infof("Add address for eni %s", id)
			addedENIByMac[eni.MAC] = eniDeviceConfig{
				name: eni.ID,
				ip: net.ParseIP(eni.IP),
			}

		}
	}

	go setupOpenStackENI(addedENIByMac)

	return nil
}

func setupOpenStackENI(eniConfigByMac configMap) {
	// Wait for the interfaces to be attached to the local node
	eniLinkByMac, err := waitForNetlinkDevices(eniConfigByMac)
	if err != nil {
		attachedENIByMac := make(map[string]string, len(eniLinkByMac))
		for mac, link := range eniLinkByMac {
			attachedENIByMac[mac] = link.Attrs().Name
		}
		requiredENIByMac := make(map[string]string, len(eniConfigByMac))
		for mac, eni := range eniConfigByMac {
			requiredENIByMac[mac] = eni.name
		}

		log.WithError(err).WithFields(logrus.Fields{
			logfields.AttachedENIs: attachedENIByMac,
			logfields.ExpectedENIs: requiredENIByMac,
		}).Error("Timed out waiting for ENIs to be attached")
	}

	// Configure new interfaces.
	for mac, link := range eniLinkByMac {
		cfg, ok := eniConfigByMac[mac]
		if !ok {
			log.WithField(logfields.MACAddr, mac).Warning("No configuration found for ENI device")
			continue
		}
		log.Infof("Add address for %s, %+v", mac, cfg)
		err = netlink.AddrAdd(link, &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   cfg.ip,
				Mask: net.CIDRMask(32, 32),
			},
		})
		if err != nil && !errors.Is(err, unix.EEXIST) {
			log.Errorf("failed to set eni primary ip address %q on link %q: %w", cfg.ip, link.Attrs().Name, err)
		}
	}
}