// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumpodippoolmonitor

import (
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"ipam-ciliumpodippool-manager",
	"Provides IPAM ciliumpodippool",

	cell.Provide(newCiliumPodIPoolMonitor),
)

type managerParams struct {
	cell.In

	Lifecycle    hive.Lifecycle
	DaemonConfig *option.DaemonConfig
	Clientset    client.Clientset
}

func newCiliumPodIPoolMonitor(params managerParams) *CiliumPodIPPoolMonitor {
	if params.DaemonConfig.KubeProxyReplacement == option.KubeProxyReplacementTrue &&
		params.DaemonConfig.IPAM == ipamOption.IPAMOpenStack {
		monitor := &CiliumPodIPPoolMonitor{
			CiliumPodIPPoolInterface: params.Clientset.CiliumV2alpha1(),
			CiliumNodeInterface:      params.Clientset.CiliumV2().CiliumNodes(),
			stop:                     make(chan struct{}),
		}
		params.Lifecycle.Append(monitor)
		return monitor
	}
	return nil
}
