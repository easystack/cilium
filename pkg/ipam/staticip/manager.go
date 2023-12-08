// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package staticip

import (
	"context"
	"fmt"
	"github.com/cilium/cilium/pkg/hive"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"golang.org/x/time/rate"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"sync"
	"time"
)

var (
	log                        = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-staticip-manager")
	staticIPStore              cache.Store
	staticIPController         cache.Controller
	ciliumStaticIPManagerQueue workqueue.RateLimitingInterface
)

type Manager struct {
	StaticIPInterface ciliumv2alpha1.CiliumV2alpha1Interface
	stop              chan struct{}
	InProgress        map[string]struct{}
	cn                *ciliumv2.CiliumNode
	sync.Mutex
}

func (m *Manager) Start(ctx hive.HookContext) (err error) {
	ciliumStaticIPManagerQueue = workqueue.NewRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(1*time.Second, 10*time.Second),
		// 20 qps, 100 bucket size.  This is only for retry speed and its only the overall factor (not per item)
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(20), 100)},
	))

	staticIPStore, staticIPController = informer.NewInformer(
		utils.ListerWatcherFromTyped[*v2alpha1.CiliumStaticIPList](m.StaticIPInterface.CiliumStaticIPs("")),
		&v2alpha1.CiliumStaticIP{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if obj.(*v2alpha1.CiliumStaticIP).Status.IPStatus == v2alpha1.Released &&
					obj.(*v2alpha1.CiliumStaticIP).Spec.NodeName == nodeTypes.GetName() {
					key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
					if err != nil {
						log.WithError(err).Warning("Unable to process CiliumStaticIP Add event")
						return
					}
					ciliumStaticIPManagerQueue.Add(key)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if newObj.(*v2alpha1.CiliumStaticIP).Status.IPStatus == v2alpha1.Released &&
					newObj.(*v2alpha1.CiliumStaticIP).Spec.NodeName == nodeTypes.GetName() {
					key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(newObj)
					if err != nil {
						log.WithError(err).Warning("Unable to process CiliumStaticIP Update event")
						return
					}
					ciliumStaticIPManagerQueue.Add(key)
				}
			},
		},
		nil,
	)
	go func() {
		staticIPController.Run(m.stop)
	}()

	cache.WaitForCacheSync(m.stop, staticIPController.HasSynced)

	go func() {
		for m.processNextWorkItem() {
		}
	}()
	return nil
}

func (m *Manager) Stop(ctx hive.HookContext) error {
	m.stop <- struct{}{}
	defer close(m.stop)
	ciliumStaticIPManagerQueue.ShutDown()
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

func (m *Manager) UpdateLocalCiliumNode(node *ciliumv2.CiliumNode) {
	m.cn = node
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

func (m *Manager) processNextWorkItem() bool {
	key, quit := ciliumStaticIPManagerQueue.Get()
	if quit {
		return false
	}
	defer ciliumStaticIPManagerQueue.Done(key)

	obj, exists, err := staticIPStore.GetByKey(key.(string))
	if err != nil || m.cn == nil {
		ciliumStaticIPManagerQueue.AddRateLimited(key)
		return true
	}

	if !exists {
		ciliumStaticIPManagerQueue.Forget(key)
		return true
	}
	csip := obj.(*v2alpha1.CiliumStaticIP)

	if m.cn.Spec.IPAM.CrdPools == nil {
		ciliumStaticIPManagerQueue.AddRateLimited(key)
		return true
	}

	found := false

	for ip, _ := range m.cn.Spec.IPAM.CrdPools[csip.Spec.Pool] {
		if ip == csip.Spec.IP {
			found = true
			break
		}
	}
	if !found {
		err = m.StaticIPInterface.CiliumStaticIPs(csip.Namespace).Delete(context.TODO(), csip.Name, v1.DeleteOptions{})
		if err == nil {
			// If err is nil we can forget it from the queue, if it is not nil
			// the queue handler will retry to process this key until it succeeds.
			ciliumStaticIPManagerQueue.Forget(key)
			return true
		}
	}
	err = fmt.Errorf("ip %s still on ciliumnode cant delete csip", csip.Spec.IP)
	log.WithError(err).Errorf("sync %q failed with %v", key, err)
	ciliumStaticIPManagerQueue.AddRateLimited(key)

	return true
}
