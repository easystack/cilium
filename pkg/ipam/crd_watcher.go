// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/watchers"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v2alpha12 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slimclientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/utils"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
	"strings"
	"sync"
	"time"
)

var (

	// crdPoolStore contains all cluster pool store as v2alpha1.CiliumPodIPPool
	crdPoolStore cache.Store

	// crdPoolStore contains all cluster csip store as v2alpha1.CiliumStaticIP
	staticIPStore cache.Store

	poolController     cache.Controller
	staticIPController cache.Controller

	// multiPoolExtraSynced is closed once the crdPoolStore is synced
	// with k8s.
	multiPoolExtraSynced = make(chan struct{})

	queueKeyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc

	// multiPoolExtraInit initialize the k8sManager
	multiPoolExtraInit sync.Once

	k8sManager = extraManager{reSyncMap: map[*Node]struct{}{}}

	creationDefaultPoolOnce sync.Once
)

const (
	defaultGCTime                  = time.Second * 10
	defaultAssignTimeOut           = time.Minute * 4
	defaultInUseTimeOut            = time.Minute * 2
	defaultWaitingForAssignTimeOut = time.Minute * 1
)

const (
	eniAddressNotFoundErr = "no address found attached in eni"
)

const (
	CiliumPodIPPoolVersion = "cilium.io/v2alpha1"
	CiliumPodIPPoolKind    = "CiliumPodIPPool"

	CiliumPodIPPoolNodeReadyStatus    = "Ready"
	CiliumPodIPPoolNodeNotReadyStatus = "NotReady"

	CreatePoolSuccessPhase = "Created crd pool success."
)

const (
	poolAnnotation = "ipam.cilium.io/openstack-ip-pool"
	poolLabel      = "openstack-ip-pool"
)

func InitIPAMOpenStackExtra(slimClient slimclientset.Interface, alphaClient v2alpha12.CiliumV2alpha1Interface, stopCh <-chan struct{}) {
	multiPoolExtraInit.Do(func() {

		poolsInit(alphaClient, stopCh)

		k8sManager.client = slimClient
		k8sManager.alphaClient = alphaClient
		staticIPInit(alphaClient, stopCh)

		k8sManager.updateCiliumNodeManagerPool()
		k8sManager.apiReady = true
		close(multiPoolExtraSynced)
	})

}

// poolsInit starts up a node watcher to handle pool events.
func poolsInit(poolGetter v2alpha12.CiliumPodIPPoolsGetter, stopCh <-chan struct{}) {
	crdPoolStore, poolController = informer.NewInformer(
		utils.ListerWatcherFromTyped[*v2alpha1.CiliumPodIPPoolList](poolGetter.CiliumPodIPPools()),
		&v2alpha1.CiliumPodIPPool{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				addPool(obj)
			},
			DeleteFunc: func(obj interface{}) {
				deletePool(obj)
			},
		},
		nil,
	)
	go func() {
		poolController.Run(stopCh)
	}()

	cache.WaitForCacheSync(stopCh, poolController.HasSynced)
}

// staticIPInit starts up a node watcher to handle csip events.
func staticIPInit(ipGetter v2alpha12.CiliumStaticIPsGetter, stopCh <-chan struct{}) {
	staticIPStore, staticIPController = informer.NewInformer(
		utils.ListerWatcherFromTyped[*v2alpha1.CiliumStaticIPList](ipGetter.CiliumStaticIPs("")),
		&v2alpha1.CiliumStaticIP{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				ipCrd := obj.(*v2alpha1.CiliumStaticIP)
				k8sManager.nodeManager.instancesAPI.ExcludeIP(ipCrd.Spec.IP)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldObj.(*v2alpha1.CiliumStaticIP).ObjectMeta.ResourceVersion == newObj.(*v2alpha1.CiliumStaticIP).ObjectMeta.ResourceVersion {
					return
				}
				ipCrd := newObj.(*v2alpha1.CiliumStaticIP)
				k8sManager.updateStaticIP(ipCrd)
			},
			DeleteFunc: func(obj interface{}) {
				ipCrd := obj.(*v2alpha1.CiliumStaticIP)
				k8sManager.nodeManager.instancesAPI.IncludeIP(ipCrd.Spec.IP)
				k8sManager.updateStaticIP(ipCrd)
			},
		},
		nil,
	)
	go func() {
		staticIPController.Run(stopCh)
	}()

	cache.WaitForCacheSync(stopCh, staticIPController.HasSynced)

	go func() {
		k8sManager.maintainStaticIPCRDs(stopCh)
	}()
}

// extraManager defines a manager responds for sync csip and pool
type extraManager struct {
	nodeManager *NodeManager
	client      slimclientset.Interface
	alphaClient v2alpha12.CiliumV2alpha1Interface
	updateMutex sync.Mutex
	reSync      bool
	reSyncMap   map[*Node]struct{}
	apiReady    bool
}

func (extraManager) requireSync(node *Node) {
	k8sManager.reSyncMap[node] = struct{}{}
	k8sManager.reSync = true
}

func (extraManager) reSyncNeeded() bool {
	return k8sManager.reSync
}

func (extraManager) reSyncCompleted() {
	k8sManager.reSync = false
	for node, _ := range k8sManager.reSyncMap {
		delete(k8sManager.reSyncMap, node)
	}
}

// ListCiliumIPPool returns all the *v2alpha1.CiliumPodIPPool from crdPoolStore
func (extraManager) ListCiliumIPPool() []*v2alpha1.CiliumPodIPPool {
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
func (extraManager) LabelNodeWithPool(nodeName string, labels map[string]string) error {
	oldNode, err := k8sManager.client.CoreV1().Nodes().Get(context.Background(), nodeName, v1.GetOptions{})
	if err != nil {
		return err
	}

	newNode := oldNode.DeepCopy()
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
	if judgeLabelDeepEqual(oldNode.GetLabels(), newLabels) {
		return nil
	}
	newNode.SetLabels(newLabels)
	_, err = k8sManager.client.CoreV1().Nodes().Update(context.Background(), newNode, v1.UpdateOptions{})

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
func (m extraManager) updateStaticIP(ipCrd *v2alpha1.CiliumStaticIP) {
	k8sManager.updateMutex.Lock()
	defer k8sManager.updateMutex.Unlock()

	node := ipCrd.Spec.NodeName
	pool := ipCrd.Spec.Pool
	ip := ipCrd.Spec.IP
	podFullName := ipCrd.Namespace + "/" + ipCrd.Name

	switch ipCrd.Status.IPStatus {
	case v2alpha1.WaitingForAssign:
		log.Infof("ready to assign ip: %v for pod: %v, on node: %v .", ip, podFullName, node)
		if n, ok := k8sManager.nodeManager.nodes[node]; ok {
			if p, ok := n.pools[Pool(pool)]; ok {
				eniID, err := p.allocateStaticIP(ip, Pool(pool))
				if err != nil {
					errMsg := fmt.Sprintf("allocate static ip: %v for pod %v failed: %s.", ip, podFullName, err)
					k8sManager.UpdateCiliumStaticIP(ipCrd, v2alpha1.WaitingForAssign, errMsg, "")
					return
				}
				// allocate static ip success, so operator need to update the ciliumnode resource.
				k8sManager.requireSync(n)
				k8sManager.UpdateCiliumStaticIP(ipCrd, v2alpha1.Assigned, "", eniID)
			} else {
				log.Errorf("can't not found pool %s on node %s, assign ip:%s for pod %s  cancel.", pool, node, ip, podFullName)
				return
			}
		} else {
			log.Errorf("can't find node %s from nodeMap failed, assign cancel.", node)
			return
		}
		log.Debugf("assign ip: %s for pod: %s success.", ip, podFullName)
	case v2alpha1.Idle:
		// before unbind the ip, we should check whether the pod is still running
		pod, exists, err := watchers.PodStore.GetByKey(podFullName)
		if err != nil {
			log.Debugf("an error occurred while get pod from podStore: %s.", err)
			return
		}
		if exists {
			// fix: Pod in Unknown status doesn't have ip.
			if pod.(*slim_corev1.Pod).Status.Phase == slim_corev1.PodRunning && pod.(*slim_corev1.Pod).Status.PodIP == ipCrd.Spec.IP {
				log.Errorf("warn: csip %s 's status is %s, but Pod is still running, which is abnormal.", ipCrd.Name, v2alpha1.Idle)
				return
			}
		}
		ipPool, err := k8sManager.GetCiliumPodIPPool(pool)
		if err != nil {
			log.Errorf("get ciliumPodIPPool failed, error is %s.", err)
			k8sManager.UpdateCiliumStaticIP(ipCrd, v2alpha1.Idle, err.Error(), "")
		} else {
			if n, ok := k8sManager.nodeManager.nodes[node]; ok {
				err = n.Ops().UnbindStaticIP(context.TODO(), ipCrd.Spec.IP, ipPool.Spec.VPCId)
				if err != nil {
					log.Errorf("unbind static ip %s failed, error is %s", ip, err)
					k8sManager.UpdateCiliumStaticIP(ipCrd, v2alpha1.Idle, err.Error(), "")
					return
				} else {
					k8sManager.UpdateCiliumStaticIP(ipCrd, v2alpha1.Unbind, "", "")
				}
			}
		}
	case v2alpha1.WaitingForRelease:
		// before we release the csip,we need to check if any pods are still occupying ip, because serious consequence may happen when skip this check.
		pod, exists, err := watchers.PodStore.GetByKey(podFullName)
		if err != nil {
			log.Debugf("an error occurred while get pod from podStore: %s.", err)
			return
		}
		if exists {
			if pod.(*slim_corev1.Pod).Status.Phase == slim_corev1.PodRunning {
				return
			}
		}
		if n, ok := k8sManager.nodeManager.nodes[node]; ok {
			if am, ok := n.resource.Spec.IPAM.CrdPools[pool]; ok {
				if _, ok := am[ip]; !ok {
					log.Debugf("ready to delete static ip %s for pod %s on node: %s", ip, podFullName, node)
					err := n.Ops().ReleaseStaticIP(ip, pool)
					if err != nil {
						errMsg := fmt.Sprintf("delete static ip: %v for pod %v failed: %s.", ip, podFullName, err)
						k8sManager.UpdateCiliumStaticIP(ipCrd, v2alpha1.WaitingForRelease, errMsg, "")
						return
					}
					log.Infof("delete static ip %s for pod %s on node %s success.", ip, podFullName, node)
					err = k8sManager.alphaClient.CiliumStaticIPs(ipCrd.Namespace).Delete(context.TODO(), ipCrd.Name, v1.DeleteOptions{})
					if err != nil {
						log.Errorf("delete csip ip: %s failed, ip is %s, err is: %s ", podFullName, ip, err)
						return
					}
				}
			}
		}
	}

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
			k8sManager.updateMutex.Lock()

			// get the newest vpc and enis from openstack api and sync the ciliumnode to apiServer
			if k8sManager.reSyncNeeded() {
				for node := range k8sManager.reSyncMap {
					node.poolMaintainer.Trigger()
					node.k8sSync.Trigger()
				}
				k8sManager.reSyncCompleted()
			}
			k8sManager.updateMutex.Unlock()

			ipCRDs := k8sManager.listStaticIPs()
			now := time.Now()

			for _, ipCrd := range ipCRDs {
				ipCopy := ipCrd.DeepCopy()
				podFullName := ipCrd.Namespace + "/" + ipCrd.Name

				switch ipCrd.Status.IPStatus {
				case v2alpha1.Unbind:
					timeout := ipCrd.Status.UpdateTime.Add(time.Second * time.Duration(ipCrd.Spec.RecycleTime))
					if !timeout.After(time.Now()) {
						ipCopy.Status.IPStatus = v2alpha1.WaitingForRelease
						_, err := k8sManager.alphaClient.CiliumStaticIPs(ipCrd.Namespace).Update(context.TODO(), ipCopy, v1.UpdateOptions{})
						if err != nil {
							log.Errorf("static ip maintainer update csip: %s failed, err is : %v", ipCrd.Name, err)
						}
					}
				case v2alpha1.Idle:
					ipCopy.Status.UpdateTime = slim_metav1.Time(v1.Time{
						Time: now,
					})
					_, err := k8sManager.alphaClient.CiliumStaticIPs(ipCopy.Namespace).Update(context.TODO(), ipCopy, v1.UpdateOptions{})
					if err != nil {
						log.Errorf("static ip maintainer update csip: %s failed, err is : %v", ipCrd.Name, err)
					}
				case v2alpha1.Assigned:
					timeout := ipCrd.Status.UpdateTime.Add(defaultAssignTimeOut)
					updateTime := ipCrd.Status.UpdateTime.Time

					if !timeout.After(now) {
						ipCopy.Status.IPStatus = v2alpha1.Idle
						ipCopy.Status.UpdateTime = slim_metav1.Time(v1.Time{
							Time: now,
						})
						_, err := k8sManager.alphaClient.CiliumStaticIPs(ipCrd.Namespace).Update(context.TODO(), ipCopy, v1.UpdateOptions{})
						if err != nil {
							log.Errorf("static ip maintainer update csip: %s failed, before status: %s, expect status: %s, err is: %s.",
								ipCopy.Name, v2alpha1.Assigned, v2alpha1.Idle, err)
						}
						// if the csip is in Assigned status, but it was not used for a long time, so we should update the ciliumnode，
						// so that the agent can see the ip is available
						// notice: 15 * time.Second is the safe time for synchronization between agent and operator
					} else if timeout.Sub(now) > 15*time.Second && now.Sub(updateTime) > 15*time.Second {
						if n, ok := k8sManager.nodeManager.nodes[ipCrd.Spec.NodeName]; ok {
							n.k8sSync.Trigger()
						}
					}
				case v2alpha1.WaitingForRelease:
					// the operator maybe not handled the WaitingForRelease csip event, so we should update the csip to be processed
					ipCopy.Status.UpdateTime = slim_metav1.Time(v1.Time{
						Time: now,
					})
					_, err := k8sManager.alphaClient.CiliumStaticIPs(ipCopy.Namespace).Update(context.TODO(), ipCopy, v1.UpdateOptions{})
					if err != nil {
						log.Errorf("static ip maintainer update csip: %s failed, status is: %s, err is: %s.",
							ipCopy.Name, v2alpha1.WaitingForAssign, err)
					}
				case v2alpha1.WaitingForAssign:
					updateTime := ipCopy.Status.UpdateTime.Time
					// the operator maybe not handled the WaitingForAssign csip event, so we back to update the csip status to Idle to be processed
					if !updateTime.Add(defaultWaitingForAssignTimeOut).After(now) {
						ipCopy.Status.IPStatus = v2alpha1.Idle
						ipCopy.Status.UpdateTime = slim_metav1.Time(v1.Time{
							Time: now,
						})
						_, err := k8sManager.alphaClient.CiliumStaticIPs(ipCrd.Namespace).Update(context.TODO(), ipCopy, v1.UpdateOptions{})
						if err != nil {
							log.Errorf("static ip maintainer update csip: %s failed, status is :%s err is : %v",
								ipCrd.Name, v2alpha1.WaitingForAssign, err)
						}
					}
				case v2alpha1.InUse:
					updateTime := ipCrd.Status.UpdateTime.Time
					if now.Sub(updateTime) < defaultInUseTimeOut {
						// csip is still in tolerant time
						continue
					}
					pod, exists, err := watchers.PodStore.GetByKey(podFullName)
					if err != nil {
						log.Debugf("an error occurred while get pod from podStore: %s.", err)
						return
					}
					if exists {
						if pod.(*slim_corev1.Pod).Status.PodIP != "" {
							continue
						}
						// if the ip address is not on the pod's node, we should unbind the ip (setting the status to Idled, unbind and assigned on next loop)
						if pod.(*slim_corev1.Pod).Spec.NodeName != ipCrd.Spec.NodeName {
							ipCopy.Status.IPStatus = v2alpha1.Idle
							ipCopy.Status.UpdateTime = slim_metav1.Time(v1.Time{
								Time: time.Now(),
							})
							_, err = k8sManager.alphaClient.CiliumStaticIPs(ipCopy.Namespace).Update(context.TODO(), ipCopy, v1.UpdateOptions{})
							if err != nil {
								log.Errorf("static ip maintainer update csip: %s failed, before status: %s, expect status: %v, err is: %v.",
									ipCopy.Name, v2alpha1.InUse, v2alpha1.Idle, err)
							}
						}
					} else {
						// the pod can't found on node store, so we consider the csip should be unbound.
						ipCopy.Status.IPStatus = v2alpha1.Idle
						ipCopy.Status.UpdateTime = slim_metav1.Time(v1.Time{
							Time: now,
						})
						_, err = k8sManager.alphaClient.CiliumStaticIPs(ipCopy.Namespace).Update(context.TODO(), ipCopy, v1.UpdateOptions{})
						if err != nil {
							log.Errorf("static ip maintainer update csip: %s failed, before status: %v, expect status: %v, err is: %v.",
								ipCopy.Name, v2alpha1.InUse, v2alpha1.Idle, err)
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

func (extraManager) updateCiliumNodeManagerPool() {
	for _, ipPool := range k8sManager.ListCiliumIPPool() {
		k8sManager.nodeManager.pools[ipPool.Name] = ipPool
	}
}

func transformToNode(obj interface{}) (interface{}, error) {
	switch concreteObj := obj.(type) {
	case *slim_corev1.Node:
		n := &slim_corev1.Node{
			TypeMeta: concreteObj.TypeMeta,
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:            concreteObj.Name,
				ResourceVersion: concreteObj.ResourceVersion,
				Annotations:     concreteObj.Annotations,
				Labels:          concreteObj.Labels,
			},
		}
		*concreteObj = slim_corev1.Node{}
		return n, nil
	case cache.DeletedFinalStateUnknown:
		node, ok := concreteObj.Obj.(*slim_corev1.Node)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &slim_corev1.Node{
				TypeMeta: node.TypeMeta,
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            node.Name,
					ResourceVersion: node.ResourceVersion,
					Annotations:     node.Annotations,
					Labels:          node.Labels,
				},
			},
		}
		// Small GC optimization
		*node = slim_corev1.Node{}
		return dfsu, nil
	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
	}
}

func addPool(obj interface{}) {
	key, _ := queueKeyFunc(obj)
	p, exists, err := crdPoolStore.GetByKey(key)
	if err != nil {
		log.Errorf("waring: crd pool store get pool: %s error %s", key, err)
	}
	if !exists {
		return
	}
	k8sManager.nodeManager.pools[key] = p.(*v2alpha1.CiliumPodIPPool)
}

func deletePool(obj interface{}) {
	key, _ := queueKeyFunc(obj)
	delete(k8sManager.nodeManager.pools, key)
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
			log.Warnf("The creation of default pool has been ignored, due to subnet-id %s not found.", defaultSubnetID)
		}
	}
	log.Warnf("The creation of default pool has been ignored, due to no subnet-id set.")
}

func (extraManager) AddFinalizerFlag(pool string, node string) error {
	ipPool, err := k8sManager.GetCiliumPodIPPool(pool)
	if err != nil {
		return err
	}
	ipPool = ipPool.DeepCopy()
	needUpdate := true
	for _, finalizer := range ipPool.Finalizers {
		if finalizer == node {
			needUpdate = false
			break
		}
	}

	if ipPool.Status.Items == nil {
		ipPool.Status.Items = map[string]v2alpha1.ItemSpec{}
	}

	if needUpdate {
		ipPool.Finalizers = append(ipPool.Finalizers, node)

	}

	if spec, hasItem := ipPool.Status.Items[node]; !hasItem || (hasItem && spec.Status != CiliumPodIPPoolNodeReadyStatus) {
		ipPool.Status.Items[node] = v2alpha1.ItemSpec{
			Phase:  CreatePoolSuccessPhase,
			Status: CiliumPodIPPoolNodeReadyStatus,
		}
		needUpdate = true
	}

	if needUpdate {
		_, err = k8sManager.alphaClient.CiliumPodIPPools().Update(context.TODO(), ipPool, v1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

func (extraManager) RemoveFinalizerFlag(pool string, node string) error {
	ipPool, err := k8sManager.GetCiliumPodIPPool(pool)
	if err != nil {
		return err
	}

	if len(ipPool.ObjectMeta.Finalizers) == 0 && ipPool.Status.Items == nil {
		return nil
	}

	var finalizers []string
	for idx, finalizer := range ipPool.ObjectMeta.Finalizers {
		if finalizer == node {
			finalizers = append(append([]string(nil), ipPool.ObjectMeta.Finalizers[:idx]...), ipPool.ObjectMeta.Finalizers[idx+1:]...)
			break
		}
	}

	ipPool = ipPool.DeepCopy()

	ipPool.ObjectMeta.Finalizers = finalizers

	delete(ipPool.Status.Items, node)

	_, err = k8sManager.alphaClient.CiliumPodIPPools().Update(context.TODO(), ipPool, v1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
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
	for _, p := range k8sManager.ListCiliumIPPool() {
		if p.Spec.CIDR == "" || p.Spec.VPCId == "" {
			if subnet, ok := subnets[p.Spec.SubnetId]; ok {
				newPool := p.DeepCopy()
				newPool.Spec.VPCId = subnet.VirtualNetworkID
				newPool.Spec.CIDR = subnet.CIDR.String()
				_, err := k8sManager.alphaClient.CiliumPodIPPools().Update(context.TODO(), newPool, v1.UpdateOptions{})
				if err != nil {
					log.Errorf("Update ciliumPodIPPool %s failed, error is %s", p.Name, err)
				}
			}
		}
	}
}
func (extraManager) UpdateCiliumIPPoolStatus(pool string, node string, status, phase string) error {
	ipPool, err := k8sManager.GetCiliumPodIPPool(pool)
	if err != nil {
		return err
	}

	ipPool = ipPool.DeepCopy()
	m := map[string]v2alpha1.ItemSpec{}
	if ipPool.Status.Items != nil {
		m = ipPool.Status.Items
	}

	m[node] = v2alpha1.ItemSpec{
		Phase:  phase,
		Status: status,
	}

	ipPool.Status.Items = m

	_, err = k8sManager.alphaClient.CiliumPodIPPools().Update(context.TODO(), ipPool, v1.UpdateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func (extraManager) UpdateCiliumStaticIP(csip *v2alpha1.CiliumStaticIP, status, phase string, eniId string) {
	now := time.Now()
	podFullName := csip.Namespace + "/" + csip.Name

	csip = csip.DeepCopy()
	if status == v2alpha1.Assigned {
		csip.Spec.ENIId = eniId
	}

	if status == v2alpha1.Unbind || status == v2alpha1.WaitingForRelease {
		csip.Spec.ENIId = ""
	}
	csip.Spec.ENIId = eniId
	csip.Status.IPStatus = status
	csip.Status.Phase = phase
	csip.Status.UpdateTime = slim_metav1.Time(v1.Time{
		Time: now,
	})
	_, err := k8sManager.alphaClient.CiliumStaticIPs(csip.Namespace).Update(context.TODO(), csip, v1.UpdateOptions{})
	if err != nil {
		log.Errorf("update statip ip status failed, when assign ip: %s for pod: %s on node: %s, error is %s.",
			csip.Spec.IP, podFullName, csip.Spec.NodeName, err)
		return
	}
}
