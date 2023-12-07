// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package staticip

import (
	"context"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"sync"
)

var (
	log                = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-staticip-manager")
	queueKeyFunc       = cache.DeletionHandlingMetaNamespaceKeyFunc
	staticIPStore      cache.Store
	staticIPController cache.Controller
)

type Manager struct {
	StaticIPInterface ciliumv2alpha1.CiliumV2alpha1Interface
	stop              chan struct{}
	InProgress        map[string]struct{}
	sync.Mutex
}

func (m *Manager) Start(ctx hive.HookContext) (err error) {
	staticIPStore, staticIPController = informer.NewInformer(
		utils.ListerWatcherFromTyped[*v2alpha1.CiliumStaticIPList](m.StaticIPInterface.CiliumStaticIPs("")),
		&v2alpha1.CiliumStaticIP{},
		0,
		cache.ResourceEventHandlerFuncs{},
		nil,
	)
	go func() {
		staticIPController.Run(m.stop)
	}()

	cache.WaitForCacheSync(m.stop, staticIPController.HasSynced)
	return nil
}

func (m *Manager) Stop(ctx hive.HookContext) error {
	m.stop <- struct{}{}
	defer close(m.stop)
	return nil
}

func (m *Manager) GetStaticIPForPod(owner string) (*v2alpha1.CiliumStaticIP, error) {
	staticIP, exists, err := staticIPStore.GetByKey(owner)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return staticIP.(*v2alpha1.CiliumStaticIP), nil
}

func (m *Manager) UpdateStaticIP(csip *v2alpha1.CiliumStaticIP, option *UpdateCSIPOption) error {
	csip, err := option.BuildModifiedCsip(csip)
	if err != nil {
		return err
	}

	for retry := 0; retry < 2; retry++ {
		_, err = m.StaticIPInterface.CiliumStaticIPs(csip.Namespace).Update(context.Background(), csip, v1.UpdateOptions{})
		if err == nil {
			break
		}
		csipFromAPIServer, err := m.StaticIPInterface.CiliumStaticIPs(csip.Namespace).Get(context.TODO(), csip.Name, v1.GetOptions{})
		if err == nil {
			csip, _ = option.BuildModifiedCsip(csipFromAPIServer)
		}
	}
	return err
}

func (m *Manager) CreateStaticIP(staticIP *v2alpha1.CiliumStaticIP) error {
	_, err := m.StaticIPInterface.CiliumStaticIPs(staticIP.Namespace).Create(context.Background(), staticIP, v1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (m *Manager) ListStaticIPs() []*v2alpha1.CiliumStaticIP {
	ipsInt := staticIPStore.List()
	out := make([]*v2alpha1.CiliumStaticIP, 0, len(ipsInt))
	for i := range ipsInt {
		out = append(out, ipsInt[i].(*v2alpha1.CiliumStaticIP))
	}
	return out
}

func (m *Manager) ListLocalReleasedCSIP() []*v2alpha1.CiliumStaticIP {
	ipsInt := staticIPStore.List()
	out := make([]*v2alpha1.CiliumStaticIP, 0, len(ipsInt))
	j := 0
	for i := range ipsInt {
		if ipsInt[i].(*v2alpha1.CiliumStaticIP).Spec.NodeName == nodeTypes.GetName() &&
			ipsInt[i].(*v2alpha1.CiliumStaticIP).Status.IPStatus == v2alpha1.Released {
			// filter out csips that belong to localNode and status is Released
			out[j] = ipsInt[i].(*v2alpha1.CiliumStaticIP)
			j++
		}
	}

	out = out[:j]
	return out
}

// IsCSIPAddress returns the csipName and if the ip is a static ip
func (m *Manager) IsCSIPAddress(address string) (string, bool) {
	for _, csip := range m.ListStaticIPs() {
		if csip.Spec.IP == address {
			return csip.Namespace + "/" + csip.Name, true
		}
	}
	return "", false
}

func (m *Manager) DeleteCSIP(namespace string, name string) error {
	return m.StaticIPInterface.CiliumStaticIPs(namespace).Delete(context.Background(), name, v1.DeleteOptions{})
}
