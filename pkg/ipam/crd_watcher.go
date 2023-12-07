// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"github.com/cilium/cilium/pkg/ipam/staticip"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"
	"k8s.io/client-go/util/workqueue"
	"strings"
	"sync"
	"time"

	operatorOption "github.com/cilium/cilium/operator/option"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v2alpha12 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimclientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/utils"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
)

var (

	// crdPoolStore contains all cluster pool store as v2alpha1.CiliumPodIPPool
	crdPoolStore cache.Store

	// crdPoolStore contains all cluster csip store as v2alpha1.CiliumStaticIP
	staticIPStore cache.Store

	poolController     cache.Controller
	staticIPController cache.Controller

	k8sManager = extraManager{ciliumStaticIPCacheSynced: make(chan struct{}), sem: semaphore.NewWeighted(20)}

	creationDefaultPoolOnce sync.Once
)

const (
	defaultGCTime                     = time.Second * 30
	defaultWaitingForReleaseSafeDelay = time.Second * 30

	DefaultMaxCreatePort     = 1024
	DefaultCPIPWatermark     = "1"
	DefaultPreallocate       = 3
	DefaultMaxAboveWaterMark = 10
)

const (
	CiliumPodIPPoolVersion = "cilium.io/v2alpha1"
	CiliumPodIPPoolKind    = "CiliumPodIPPool"
)

const (
	poolAnnotation = "ipam.cilium.io/openstack-ip-pool"
	poolLabel      = "openstack-ip-pool"
)

var (
	resourceEventHandler       cache.ResourceEventHandlerFuncs
	ciliumStaticIPManagerQueue workqueue.RateLimitingInterface
	ciliumStaticIPSyncHandler  func(key string) error
)

func InitIPAMOpenStackExtra(slimClient slimclientset.Interface, alphaClient v2alpha12.CiliumV2alpha1Interface, stopCh <-chan struct{}) {
	poolsInit(alphaClient, stopCh)
	k8sManager.client = slimClient
	k8sManager.alphaClient = alphaClient
	staticIPInit(alphaClient, stopCh)

	k8sManager.apiReady = true
}

// poolsInit starts up a node watcher to handle pool events.
func poolsInit(poolGetter v2alpha12.CiliumPodIPPoolsGetter, stopCh <-chan struct{}) {
	crdPoolStore, poolController = informer.NewInformer(
		utils.ListerWatcherFromTyped[*v2alpha1.CiliumPodIPPoolList](poolGetter.CiliumPodIPPools()),
		&v2alpha1.CiliumPodIPPool{},
		0,
		cache.ResourceEventHandlerFuncs{},
		nil,
	)
	go func() {
		poolController.Run(stopCh)
	}()

	cache.WaitForCacheSync(stopCh, poolController.HasSynced)
}

// staticIPInit starts up a node watcher to handle csip events.
func staticIPInit(ipGetter v2alpha12.CiliumStaticIPsGetter, stopCh <-chan struct{}) {
	ciliumStaticIPManagerQueue = workqueue.NewRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(5*time.Second, 200*time.Second),
		// 20 qps, 100 bucket size.  This is only for retry speed and its only the overall factor (not per item)
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(20), 200)},
	))

	resourceEventHandler = cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err != nil {
				log.WithError(err).Warning("Unable to process CiliumStaticIP Add event")
				return
			}
			ipCrd := obj.(*v2alpha1.CiliumStaticIP)
			k8sManager.nodeManager.instancesAPI.ExcludeIP(ipCrd.Spec.IP)
			ciliumStaticIPManagerQueue.Add(key)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if oldCSIP := objToCiliumStaticIP(oldObj); oldCSIP != nil {
				if newCSIP := objToCiliumStaticIP(newObj); newCSIP != nil {
					if oldCSIP.DeepEqual(newCSIP) {
						return
					}
					key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(newObj)
					if err != nil {
						log.WithError(err).Warning("Unable to process CiliumStaticIP Update event")
						return
					}
					if newCSIP.Status.IPStatus == v2alpha1.InUse ||
						newCSIP.Status.IPStatus == v2alpha1.Assigned ||
						newCSIP.Status.IPStatus == v2alpha1.Released {
						return
					}
					ciliumStaticIPManagerQueue.Add(key)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			if csip := obj.(*v2alpha1.CiliumStaticIP); csip.Status.IPStatus == v2alpha1.Released {
				k8sManager.nodeManager.instancesAPI.IncludeIP(obj.(*v2alpha1.CiliumStaticIP).Spec.IP)
			}

		},
	}

	staticIPStore, staticIPController = informer.NewInformer(
		utils.ListerWatcherFromTyped[*v2alpha1.CiliumStaticIPList](ipGetter.CiliumStaticIPs("")),
		&v2alpha1.CiliumStaticIP{},
		0,
		resourceEventHandler,
		nil,
	)
	go func() {
		staticIPController.Run(stopCh)
		ciliumStaticIPManagerQueue.ShutDown()
	}()

	ciliumStaticIPSyncHandler = k8sManager.syncHandlerConstructor(
		func(csip *v2alpha1.CiliumStaticIP) error {
			return k8sManager.updateStaticIP(csip)
		})

	go func() {
		cache.WaitForCacheSync(stopCh, staticIPController.HasSynced)
		close(k8sManager.ciliumStaticIPCacheSynced)
		log.Info("CiliumStaticIP caches synced with Kubernetes")

		k8sManager.maintainStaticIPCRDs(stopCh)
	}()

	<-k8sManager.ciliumStaticIPCacheSynced
	go func() {
		// infinite loop. run in a goroutine to unblock code execution
		for k8sManager.processNextWorkItem(ciliumStaticIPSyncHandler) {
		}
	}()

}

// extraManager defines a manager responds for sync csip and pool
type extraManager struct {
	nodeManager               *NodeManager
	client                    slimclientset.Interface
	alphaClient               v2alpha12.CiliumV2alpha1Interface
	apiReady                  bool
	ciliumStaticIPCacheSynced chan struct{}
	sem                       *semaphore.Weighted
}

// ListCiliumIPPool returns all the *v2alpha1.CiliumPodIPPool from crdPoolStore
func ListCiliumIPPool() []*v2alpha1.CiliumPodIPPool {
	if crdPoolStore == nil {
		log.Infoln("### crd pool store is not ready")
		return nil
	}
	poolsInt := crdPoolStore.List()
	out := make([]*v2alpha1.CiliumPodIPPool, 0, len(poolsInt))
	for i := range poolsInt {
		out = append(out, poolsInt[i].(*v2alpha1.CiliumPodIPPool))
	}
	return out
}

// GetCiliumPodIPPool returns *v2alpha1.CiliumPodIPPool by name which stored in crdPoolStore
func (extraManager) GetCiliumPodIPPool(name string) (*v2alpha1.CiliumPodIPPool, error) {
	poolInterface, exists, err := crdPoolStore.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8sErrors.NewNotFound(schema.GroupResource{
			Group:    "cilium.io",
			Resource: "CiliumPodIPPool",
		}, name)
	}
	return poolInterface.(*v2alpha1.CiliumPodIPPool), nil
}

// LabelNodeWithPool relabel the node with provided labels map
func (extraManager) LabelNodeWithPool(labels map[string]string, node slim_corev1.Node) error {

	newNode := node.DeepCopy()
	newLabels := newNode.GetLabels()

	// remove all the old pool label
	for k, _ := range newLabels {
		if strings.HasPrefix(k, poolLabel) {
			delete(newLabels, k)
		}
	}

	// label all the updated pool
	for k, v := range labels {
		newLabels[k] = v
	}
	if judgeLabelDeepEqual(node.GetLabels(), newLabels) {
		return nil
	}
	newNode.SetLabels(newLabels)
	_, err := k8sManager.client.CoreV1().Nodes().Update(context.Background(), newNode, v1.UpdateOptions{})

	return err
}

func judgeLabelDeepEqual(old, new map[string]string) bool {
	if ((old != nil) && (new != nil)) || ((old == nil) != (new == nil)) {
		in, other := &old, &new
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for key, inValue := range *in {
				if otherValue, present := (*other)[key]; !present {
					return false
				} else {
					if inValue != otherValue {
						return false
					}
				}
			}
		}
	}
	return true
}

// updateStaticIP responds for reconcile the csip event
func (m extraManager) updateStaticIP(ipCrd *v2alpha1.CiliumStaticIP) error {
	node := ipCrd.Spec.NodeName
	pool := ipCrd.Spec.Pool
	ip := ipCrd.Spec.IP
	podFullName := ipCrd.Namespace + "/" + ipCrd.Name

	switch ipCrd.Status.IPStatus {
	case v2alpha1.WaitingForAssign:
		log.Debugf("ready to assign ip: %v for pod: %v, on node: %v .", ip, podFullName, node)
		if n, ok := k8sManager.nodeManager.nodes[node]; ok {
			if p, ok := n.pools[Pool(pool)]; ok {
				portId, eniID, err := p.allocateStaticIP(ip, Pool(pool), ipCrd.Spec.PortId)
				if err != nil {
					return fmt.Errorf("allocate static ip: %v for pod %v failed: %s", ip, podFullName, err)
				}
				option := staticip.NewUpdateCSIPOption().WithENIId(eniID).WithPortId(portId).WithStatus(v2alpha1.Assigned)
				err = k8sManager.UpdateStaticIP(podFullName, option)
				if err != nil {
					return err
				}
			} else {
				return fmt.Errorf("can't not found pool %s on node %s, assign ip:%s for pod %s  cancel.", pool, node, ip, podFullName)
			}
		} else {
			return fmt.Errorf("can't find node %s from nodeMap failed, assign cancel", node)
		}
		log.Debugf("assign ip: %s for pod: %s success.", ip, podFullName)
	case v2alpha1.Idle:
		ipPool, err := k8sManager.GetCiliumPodIPPool(pool)
		if err != nil {
			return err
		} else {
			if n, ok := k8sManager.nodeManager.nodes[node]; ok {
				err = n.Ops().UnbindStaticIP(context.TODO(), ipCrd.Spec.IP, ipPool.Spec.VPCId)
				if err != nil {
					return fmt.Errorf("unbind static ip %s failed, error is %s", ip, err)
				} else {
					option := staticip.NewUpdateCSIPOption().WithStatus(v2alpha1.Unbind)
					err := k8sManager.UpdateStaticIP(podFullName, option)
					if err != nil {
						return err
					}
				}
			} else {
				return fmt.Errorf("node %s not found", node)
			}
		}
	case v2alpha1.WaitingForRelease:
		if n, ok := k8sManager.nodeManager.nodes[node]; ok {
			if am, ok := n.resource.Spec.IPAM.CrdPools[pool]; ok {
				if _, ok := am[ip]; !ok {
					log.Debugf("ready to delete static ip %s for pod %s on node: %s", ip, podFullName, node)
					err := n.Ops().ReleaseStaticIP(ip, pool, ipCrd.Spec.PortId)
					if err != nil {
						return fmt.Errorf("release static ip: %v for pod %v failed: %s", ip, podFullName, err)
					}
					option := staticip.NewUpdateCSIPOption().WithStatus(v2alpha1.Released)
					err = k8sManager.UpdateStaticIP(podFullName, option)
					if err != nil {
						return err
					}
				}
			} else {
				return fmt.Errorf("pool %s not found on node %s, please check it", pool, node)
			}
		} else {
			return fmt.Errorf("node %s not found, please check it", node)
		}
	}
	return nil
}

// listStaticIPs returns all the csip crds which stored in staticIPStore
func (extraManager) listStaticIPs() []*v2alpha1.CiliumStaticIP {
	ipsInt := staticIPStore.List()
	out := make([]*v2alpha1.CiliumStaticIP, 0, len(ipsInt))
	for i := range ipsInt {
		out = append(out, ipsInt[i].(*v2alpha1.CiliumStaticIP))
	}
	return out
}

// maintainStaticIPCRDs maintain the csips, the time interval is defaultGCTime
func (extraManager) maintainStaticIPCRDs(stop <-chan struct{}) {
	log.Debugln("static ip maintainer started.")
	for {
		select {
		case <-time.After(defaultGCTime):
			ipCRDs := k8sManager.listStaticIPs()
			for _, ipCrd := range ipCRDs {
				if ipCrd.Status.IPStatus == v2alpha1.Unbind {
					timeout := ipCrd.Status.UpdateTime.Add(time.Second * time.Duration(ipCrd.Spec.RecycleTime)).Add(defaultWaitingForReleaseSafeDelay)
					if !timeout.After(time.Now()) {
						option := staticip.NewUpdateCSIPOption().WithStatus(v2alpha1.WaitingForRelease)
						fullName := ipCrd.Namespace + "/" + ipCrd.Name
						err := k8sManager.UpdateStaticIP(fullName, option)
						if err != nil {
							log.Errorf("static ip maintainer update csip: %s failed, err is : %v", ipCrd.Name, err)
						}
					}
				}
			}
		case <-stop:
			log.Debugln("static ip maintainer stopped")
			return
		}
	}
}

func (extraManager) CreateDefaultPool(subnets ipamTypes.SubnetMap) {
	if defaultSubnetID := operatorOption.Config.OpenStackDefaultSubnetID; defaultSubnetID != "" {
		if subnet, ok := subnets[defaultSubnetID]; ok {
			defaultPool := &v2alpha1.CiliumPodIPPool{
				TypeMeta: v1.TypeMeta{
					APIVersion: CiliumPodIPPoolVersion,
					Kind:       CiliumPodIPPoolKind,
				},
				ObjectMeta: v1.ObjectMeta{
					Name: string(PoolDefault),
				},
				Spec: v2alpha1.IPPoolSpec{
					SubnetId: defaultSubnetID,
					CIDR:     subnet.CIDR.String(),
					VPCId:    subnet.VirtualNetworkID,
				},
			}
			_, err := k8sManager.alphaClient.CiliumPodIPPools().Create(context.TODO(), defaultPool, v1.CreateOptions{})
			if err != nil && !k8sErrors.IsAlreadyExists(err) {
				log.Errorf("An error occurred during the creation of default pool, subnet-id is: %s, error is %s.", defaultSubnetID, err.Error())
				return
			} else {
				log.Infof("Successfully created the default pool, subnet-id is %s", defaultSubnetID)
				return
			}
		} else {
			log.Fatalf("The creation of default pool has been ignored, due to default-subnetID %s not found from neutron.", defaultSubnetID)
		}
	}
	log.Fatalf("The creation of default pool has been ignored, due to no default-subnetID set.")
}

func SyncPoolToAPIServer(subnets ipamTypes.SubnetMap) {
	if !k8sManager.apiReady {
		return
	}
	creationDefaultPoolOnce.Do(
		func() {
			k8sManager.CreateDefaultPool(subnets)
		},
	)

	cpips := ListCiliumIPPool()
	subnetToCpip := map[string]string{}
	j := 0

	for _, cpip := range cpips {
		if cpip.Status.Active == true {
			// record the pools that already active
			subnetToCpip[cpip.Spec.SubnetId] = cpip.Name
			continue
		}

		cpips[j] = cpip
		j++
	}

	// filter out subnets which inActive
	cpips = cpips[:j]

	for _, cpip := range cpips {
		subnetId := cpip.Spec.SubnetId

		// the pools cannot have the same subnet
		if _, exist := subnetToCpip[subnetId]; !exist {
			if subnet, ok := subnets[subnetId]; ok {
				newPool := cpip.DeepCopy()
				newPool.Spec.VPCId = subnet.VirtualNetworkID
				newPool.Spec.CIDR = subnet.CIDR.String()
				newPool.Status.Active = true
				if newPool.Spec.Watermark == "" {
					newPool.Spec.Watermark = DefaultCPIPWatermark
				}
				if newPool.Spec.MaxFreePort == 0 {
					newPool.Spec.MaxFreePort = DefaultMaxCreatePort
				}
				if newPool.Spec.NodeMaxAboveWatermark == 0 {
					newPool.Spec.NodeMaxAboveWatermark = DefaultMaxAboveWaterMark
				}
				if newPool.Spec.NodePreAllocate == 0 {
					newPool.Spec.NodePreAllocate = DefaultPreallocate
				}

				_, err := k8sManager.alphaClient.CiliumPodIPPools().Update(context.TODO(), newPool, v1.UpdateOptions{})
				if err != nil {
					log.Errorf("Update ciliumPodIPPool %s failed, error is %s", cpip.Name, err)
				} else {
					subnetToCpip[subnetId] = cpip.Name
				}
			} else {
				log.Errorf("#### the subnet-id %s can not found from neutron.", subnetId)
			}
		} else {
			log.Errorf("#### here's already a cpip for subnet-ID %s, so cpip %s can not be activated", subnetId, cpip.Name)
		}
	}
}
func UpdateCiliumIPPoolStatus(pool string, items map[string]v2alpha1.ItemSpec, curFreePort int, reachedMaxPorts bool, finalizerFlag []string) error {
	ipPool, err := k8sManager.GetCiliumPodIPPool(pool)
	if err != nil {
		return err
	}

	ipPool = ipPool.DeepCopy()

	if items != nil {
		ipPool.Status.Items = items
	}
	if finalizerFlag != nil {
		ipPool.Finalizers = finalizerFlag
	}

	if curFreePort != -1 {
		ipPool.Status.CurrentFreePort = curFreePort
	}

	if reachedMaxPorts {
		ipPool.Status.MaxPortsReached = true
	}

	_, err = k8sManager.alphaClient.CiliumPodIPPools().Update(context.TODO(), ipPool, v1.UpdateOptions{})
	if err != nil {
		if items == nil && finalizerFlag == nil {
			return err
		}
		ipPool, err = k8sManager.alphaClient.CiliumPodIPPools().Get(context.TODO(), pool, v1.GetOptions{})
		if err != nil {
			if items != nil {
				ipPool.Status.Items = items
			}
			if finalizerFlag != nil {
				ipPool.Finalizers = finalizerFlag
			}
			_, err = k8sManager.alphaClient.CiliumPodIPPools().Update(context.TODO(), ipPool, v1.UpdateOptions{})
			if err != nil {
				log.Errorf("back to get and update ciliumPodIPPool failed, error is %s", err)
				return err
			}
		}
	}

	return nil
}

func (extraManager) UpdateStaticIP(fullName string, option *staticip.UpdateCSIPOption) error {
	c, exists, err := staticIPStore.GetByKey(fullName)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("csip for %s not found", fullName)
	}
	csip, err := option.BuildModifiedCsip(c.(*v2alpha1.CiliumStaticIP))
	if err != nil {
		return err
	}

	for retry := 0; retry < 2; retry++ {
		_, err = k8sManager.alphaClient.CiliumStaticIPs(csip.Namespace).Update(context.Background(), csip, v1.UpdateOptions{})
		if err == nil {
			break
		}
		csipFromAPIServer, err := k8sManager.alphaClient.CiliumStaticIPs(csip.Namespace).Get(context.TODO(), csip.Name, v1.GetOptions{})
		if err == nil {
			csip, _ = option.BuildModifiedCsip(csipFromAPIServer)
		}
	}
	return err
}

type perPoolSpec struct {
	mutex sync.Mutex
	spec  map[string]v2alpha1.ItemSpec
}

func (poolSpec *perPoolSpec) updatePerPoolSpec(node string, spec v2alpha1.ItemSpec) {
	poolSpec.mutex.Lock()
	poolSpec.spec[node] = spec
	poolSpec.mutex.Unlock()
	return
}

func (poolSpec *perPoolSpec) getSpecData() map[string]v2alpha1.ItemSpec {
	return poolSpec.spec
}

// processNextWorkItem process all events from the workqueue.
func (extraManager) processNextWorkItem(syncHandler func(key string) error) bool {
	key, quit := ciliumStaticIPManagerQueue.Get()
	if quit {
		return false
	}
	defer ciliumStaticIPManagerQueue.Done(key)

	log.Infof("process csip %s", key.(string))
	k8sManager.sem.Acquire(context.TODO(), 1)

	go func(key interface{}) {
		defer k8sManager.sem.Release(1)
		err := syncHandler(key.(string))
		if err == nil {
			// If err is nil we can forget it from the queue, if it is not nil
			// the queue handler will retry to process this key until it succeeds.
			ciliumStaticIPManagerQueue.Forget(key)
			return
		}
		log.Errorf("err: %s , err: %v", err, err == nil)

		log.WithError(err).Errorf("sync %q failed with %v", key, err)
		ciliumStaticIPManagerQueue.AddRateLimited(key)
	}(key)

	return true
}

// objToCiliumStaticIP attempts to cast object to a CiliumStaticIP object and
// returns the CiliumStaticIP objext if the cast succeeds. Otherwise, nil is returned.
func objToCiliumStaticIP(obj interface{}) *v2alpha1.CiliumStaticIP {
	cn, ok := obj.(*v2alpha1.CiliumStaticIP)
	if ok {
		return cn
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		cn, ok := deletedObj.Obj.(*v2alpha1.CiliumStaticIP)
		if ok {
			return cn
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid v2Alpha1 ciliumStaticIP")
	return nil
}

func (extraManager) syncHandlerConstructor(foundHandler func(node *v2alpha1.CiliumStaticIP) error) func(key string) error {
	return func(key string) error {
		obj, exists, err := staticIPStore.GetByKey(key)

		// Delete handling
		if !exists || k8sErrors.IsNotFound(err) {
			return nil
		}

		if err != nil {
			log.WithError(err).Warning("Unable to retrieve CiliumStaticIP from watcher store")
			return err
		}

		csip, ok := obj.(*v2alpha1.CiliumStaticIP)
		if !ok {
			tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
			if !ok {
				return fmt.Errorf("couldn't get object from tombstone %T", obj)
			}
			csip, ok = tombstone.Obj.(*v2alpha1.CiliumStaticIP)
			if !ok {
				return fmt.Errorf("tombstone contained object that is not a *cilium_v2.CiliumNode %T", obj)
			}
		}

		if csip.DeletionTimestamp != nil {
			return nil
		}
		return foundHandler(csip)
	}
}
