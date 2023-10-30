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

func (m *Manager) UpdateStaticIPStatus(staticIP *v2alpha1.CiliumStaticIP) error {
	_, err := m.StaticIPInterface.CiliumStaticIPs(staticIP.Namespace).Update(context.Background(), staticIP, v1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
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

// IsCSIPAddress returns the csipName and if the ip is a static ip
func (m *Manager) IsCSIPAddress(address string) (string, bool) {
	for _, csip := range m.ListStaticIPs() {
		if csip.Spec.IP == address {
			return csip.Namespace + "/" + csip.Name, true
		}
	}
	return "", false
}
