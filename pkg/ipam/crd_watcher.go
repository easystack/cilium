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
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
	"strings"
	"sync"
	"time"
)

var (
	// slimNodeStore contains all cluster nodes store as slim_core.Node
	slimNodeStore cache.Store

	// crdPoolStore contains all cluster pool store as v2alpha1.CiliumPodIPPool
	crdPoolStore cache.Store

	// crdPoolStore contains all cluster csip store as v2alpha1.CiliumStaticIP
	staticIPStore cache.Store

	nodeController     cache.Controller
	poolController     cache.Controller
	staticIPController cache.Controller

	// multiPoolExtraSynced is closed once the slimNodeStore and crdPoolStore is synced
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
)

type set map[string]struct{}
type poolSet map[string]poolState
type poolState int

const (
	poolAnnotation = "ipam.cilium.io/openstack-ip-pool"
	poolLabel      = "openstack-ip-pool"
)

type extraOperation interface {
	ListK8sSlimNode() []*slim_corev1.Node
	GetK8sSlimNode(nodeName string) (*slim_corev1.Node, error)
	LabelNodeWithPool(nodeName string, labels map[string]string) error
	ListCiliumIPPool() []*v2alpha1.CiliumPodIPPool
	updateCiliumNodeManagerPool()
	listStaticIPs() []*v2alpha1.CiliumStaticIP
}

func InitIPAMOpenStackExtra(slimClient slimclientset.Interface, alphaClient v2alpha12.CiliumV2alpha1Interface, stopCh <-chan struct{}) {
	multiPoolExtraInit.Do(func() {

		nodesInit(slimClient, stopCh)
		poolsInit(alphaClient, stopCh)

		k8sManager.client = slimClient
		k8sManager.alphaClient = alphaClient
		staticIPInit(alphaClient, stopCh)

		k8sManager.updateCiliumNodeManagerPool()
		k8sManager.apiReady = true
		close(multiPoolExtraSynced)
	})

}

// nodesInit starts up a node watcher to handle node events.
func nodesInit(slimClient slimclientset.Interface, stopCh <-chan struct{}) {
	slimNodeStore, nodeController = informer.NewInformer(
		utils.ListerWatcherFromTyped[*slim_corev1.NodeList](slimClient.CoreV1().Nodes()),
		&slim_corev1.Node{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				updateNode(obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				// little optimize for invoke updateNode
				if compareNodeAnnotationAndLabelChange(oldObj, newObj) {
					updateNode(newObj)
				}
			},
		},
		transformToNode,
	)
	go func() {
		nodeController.Run(stopCh)
	}()

	cache.WaitForCacheSync(stopCh, nodeController.HasSynced)
}

// poolsInit starts up a node watcher to handle pool events.
func poolsInit(poolGetter v2alpha12.CiliumPodIPPoolsGetter, stopCh <-chan struct{}) {
	crdPoolStore, poolController = informer.NewInformer(
		utils.ListerWatcherFromTyped[*v2alpha1.CiliumPodIPPoolList](poolGetter.CiliumPodIPPools()),
		&v2alpha1.CiliumPodIPPool{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				updatePool(obj)
			},
			DeleteFunc: func(obj interface{}) {
				deletePool(obj)
			},
		},
		transformToPool,
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
				ipCopy := newObj.(*v2alpha1.CiliumStaticIP).DeepCopy()
				k8sManager.updateStaticIP(ipCopy)
			},
			DeleteFunc: func(obj interface{}) {
				ipCrd := obj.(*v2alpha1.CiliumStaticIP)
				k8sManager.nodeManager.instancesAPI.IncludeIP(ipCrd.Spec.IP)
				k8sManager.updateStaticIP(ipCrd)
			},
		},
		transformToStaticIP,
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

// ListK8sSlimNode returns all the *slim_corev1.Node from slimNodeStore
func (extraManager) ListK8sSlimNode() []*slim_corev1.Node {
	nodesInt := slimNodeStore.List()
	out := make([]*slim_corev1.Node, 0, len(nodesInt))
	for i := range nodesInt {
		out = append(out, nodesInt[i].(*slim_corev1.Node))
	}
	return out
}

// GetK8sSlimNode returns *slim_corev1.Node by nodeName which stored in slimNodeStore
func (extraManager) GetK8sSlimNode(nodeName string) (*slim_corev1.Node, error) {
	nodeInterface, exists, err := slimNodeStore.GetByKey(nodeName)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8sErrors.NewNotFound(schema.GroupResource{
			Group:    "core",
			Resource: "Node",
		}, nodeName)
	}
	return nodeInterface.(*slim_corev1.Node), nil
}

// LabelNodeWithPool relabel the node with provided labels map
func (extraManager) LabelNodeWithPool(nodeName string, labels map[string]string) error {
	oldNode, err := k8sManager.client.CoreV1().Nodes().Get(context.Background(), nodeName, v1.GetOptions{})
	if err != nil {
		return err
	}
	oldLabel := oldNode.GetLabels()

	// remove all the old pool label
	for k, _ := range oldLabel {
		if strings.HasPrefix(k, poolLabel) {
			delete(oldLabel, k)
		}
	}

	// label all the updated pool
	for k, v := range labels {
		oldLabel[k] = v
	}
	oldNode.SetLabels(oldLabel)
	_, err = k8sManager.client.CoreV1().Nodes().Update(context.Background(), oldNode, v1.UpdateOptions{})
	return err
}

func compareNodeAnnotationAndLabelChange(oldObj, newObj interface{}) bool {
	oldAccessor, _ := meta.Accessor(oldObj)
	newAccessor, _ := meta.Accessor(newObj)

	oldLabels := oldAccessor.GetLabels()
	newLabels := newAccessor.GetLabels()

	if oldLabels == nil {
		oldLabels = map[string]string{}
	}

	for newLabel, _ := range newLabels {
		if strings.HasPrefix(newLabel, poolLabel) {
			if _, has := oldLabels[newLabel]; !has {
				return true
			}
		}
	}

	}

	return false
}

func transformToStaticIP(obj interface{}) (interface{}, error) {
	switch concreteObj := obj.(type) {
	case *v2alpha1.CiliumStaticIP:
		n := &v2alpha1.CiliumStaticIP{
			TypeMeta: v1.TypeMeta{
				Kind:       concreteObj.Kind,
				APIVersion: concreteObj.APIVersion,
			},
			ObjectMeta: v1.ObjectMeta{
				Name:            concreteObj.Name,
				ResourceVersion: concreteObj.ResourceVersion,
				Namespace:       concreteObj.Namespace,
			},
			Spec: v2alpha1.StaticIPSpec{
				IP:          concreteObj.Spec.IP,
				NodeName:    concreteObj.Spec.NodeName,
				Pool:        concreteObj.Spec.Pool,
				RecycleTime: concreteObj.Spec.RecycleTime,
			},
			Status: v2alpha1.StaticIPStatus{
				IPStatus:   concreteObj.Status.IPStatus,
				UpdateTime: concreteObj.Status.UpdateTime,
			},
		}
		*concreteObj = v2alpha1.CiliumStaticIP{}
		return n, nil
	case cache.DeletedFinalStateUnknown:
		p, ok := concreteObj.Obj.(*v2alpha1.CiliumStaticIP)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &v2alpha1.CiliumStaticIP{
				TypeMeta: p.TypeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name:            p.Name,
					ResourceVersion: p.ResourceVersion,
					Namespace:       p.Namespace,
				},
				Spec: v2alpha1.StaticIPSpec{
					IP:          p.Spec.IP,
					NodeName:    p.Spec.NodeName,
					Pool:        p.Spec.Pool,
					RecycleTime: p.Spec.RecycleTime,
				},
				Status: v2alpha1.StaticIPStatus{
					IPStatus:   p.Status.IPStatus,
					UpdateTime: p.Status.UpdateTime,
				},
			},
		}
		// Small GC optimization
		*p = v2alpha1.CiliumStaticIP{}
		return dfsu, nil
	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
	}
}

// updateStaticIP responds for reconcile the csip event
func (m extraManager) updateStaticIP(ipCrd *v2alpha1.CiliumStaticIP) {
	k8sManager.updateMutex.Lock()
	defer k8sManager.updateMutex.Unlock()

	node := ipCrd.Spec.NodeName
	pool := ipCrd.Spec.Pool
	ip := ipCrd.Spec.IP
	podFullName := ipCrd.Namespace + "/" + ipCrd.Name
	now := time.Now()

	switch ipCrd.Status.IPStatus {
	case v2alpha1.WaitingForAssign:
		log.Infof("ready to assign ip: %v for pod: %v, on node: %v .", ip, podFullName, node)
		if n, ok := k8sManager.nodeManager.nodes[node]; ok {
			if p, ok := n.pools[Pool(pool)]; ok {
				err := p.allocateStaticIP(ip, Pool(pool))
				if err != nil {
					errMsg := fmt.Sprintf("allocate static ip: %v for pod %v failed: %s.", ip, podFullName, err)
					ipCrd.Status.Phase = errMsg
					_, err = k8sManager.alphaClient.CiliumStaticIPs(ipCrd.Namespace).Update(context.TODO(), ipCrd, v1.UpdateOptions{})
					if err != nil {
						log.Errorf("update statip ip status failed, when assign ip: %s for pod: %s on node: %s, error is %s.",
							ip, podFullName, node, err)
					}
					return
				}
				// allocate static ip success, so operator need to update the ciliumnode resource.
				k8sManager.requireSync(n)
				ipCrd.Status.IPStatus = v2alpha1.Assigned
				ipCrd.Status.UpdateTime = slim_metav1.Time(v1.Time{
					Time: now,
				})
				_, err = k8sManager.alphaClient.CiliumStaticIPs(ipCrd.Namespace).Update(context.TODO(), ipCrd, v1.UpdateOptions{})
				if err != nil {
					log.Errorf("update statip ip status failed, when assign ip: %s for pod: %s on node: %s, error is %s.",
						ip, podFullName, node, err)
					return
				}
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
		if n, ok := k8sManager.nodeManager.nodes[node]; ok {
			if am, ok := n.resource.Spec.IPAM.CrdPools[pool]; ok {
				if a, ok := am[ip]; ok {
					if a.Resource != "" {
						action := &ReleaseAction{
							InterfaceID: a.Resource,
							IPsToRelease: []string{
								ip,
							},
						}
						// before unbind the ip, we should check whether the pod is still running
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
						log.Debugf("ready to unbind static ip %s for pod %s on node: %s", ip, podFullName, node)
						err = n.Ops().UnbindStaticIP(context.TODO(), action, pool)
						if err != nil && !strings.Contains(err.Error(), eniAddressNotFoundErr) {
							errMsg := fmt.Sprintf("unbind static ip: %v for pod %v failed: %s.", ip, podFullName, err)
							ipCrd.Status.Phase = errMsg
							_, err = k8sManager.alphaClient.CiliumStaticIPs(ipCrd.Namespace).Update(context.TODO(), ipCrd, v1.UpdateOptions{})
							if err != nil {
								log.Errorf("update statip ip status failed, when unbind ip: %s for pod: %s on node: %s, error is %s.",
									ip, podFullName, node, err)
							}
							return
						}
						log.Infof("unbind static ip %s for pod %s on node %s success.", ip, podFullName, node)
						k8sManager.requireSync(n)
						ipCrd.Status.IPStatus = v2alpha1.Unbind
						ipCrd.Status.UpdateTime = slim_metav1.Time(v1.Time{
							Time: now,
						})
						_, err = k8sManager.alphaClient.CiliumStaticIPs(ipCrd.Namespace).Update(context.TODO(), ipCrd, v1.UpdateOptions{})
						if err != nil {
							log.Errorf("update statip ip status failed, when unbind ip: %s for pod: %s on node: %s, error is %s.",
								ip, podFullName, node, err)
						}
						log.Debugf("unbind static ip %s for pod %s on node: %s success.", ip, podFullName, node)
						return
					}
				} else {
					// eni seems not appeared on crdPools,so we back try to unbind ip from ciliumnode status
					attached := false
					interfaceID := ""
					for i, eni := range n.resource.Status.OpenStack.ENIs {
						for _, sip := range eni.SecondaryIPSets {
							if sip.IpAddress == ip {
								interfaceID = i
								attached = true
								goto release
							}
						}
					}
				release:
					if attached {
						log.Debugf("ready to unbind static ip %s for pod %s on node: %s", ip, podFullName, node)
						action := &ReleaseAction{
							InterfaceID: interfaceID,
							IPsToRelease: []string{
								ip,
							},
						}
						err := n.Ops().UnbindStaticIP(context.TODO(), action, pool)
						if err != nil && !strings.Contains(err.Error(), eniAddressNotFoundErr) {
							errMsg := fmt.Sprintf("unbind static ip: %v for pod %v failed: %s.", ip, podFullName, err)
							ipCrd.Status.Phase = errMsg
							_, err = k8sManager.alphaClient.CiliumStaticIPs(ipCrd.Namespace).Update(context.TODO(), ipCrd, v1.UpdateOptions{})
							if err != nil {
								log.Errorf("update statip ip status failed, when unbind ip: %s for pod: %s on node: %s, error is %s.",
									ip, podFullName, node, err)
							}
							return
						}
						k8sManager.requireSync(n)
						ipCrd.Status.IPStatus = v2alpha1.Unbind
						ipCrd.Status.UpdateTime = slim_metav1.Time(v1.Time{
							Time: now,
						})
						_, err = k8sManager.alphaClient.CiliumStaticIPs(ipCrd.Namespace).Update(context.TODO(), ipCrd, v1.UpdateOptions{})
						if err != nil {
							log.Errorf("update statip ip status failed, when unbind ip: %s for pod: %s on node: %s, error is %s.",
								ip, podFullName, node, err)
						}
						log.Debugf("unbind static ip %s for pod %s on node: %s success.", ip, podFullName, node)
						return
					} else {
						// static ip seems already unbound, so we just need to update the csip status
						ipCrd.Status.IPStatus = v2alpha1.Unbind
						ipCrd.Status.UpdateTime = slim_metav1.Time(v1.Time{
							Time: now,
						})
						_, err := k8sManager.alphaClient.CiliumStaticIPs(ipCrd.Namespace).Update(context.TODO(), ipCrd, v1.UpdateOptions{})
						if err != nil {
							log.Errorf("update statip ip status failed, when unbind ip: %s for pod: %s on node: %s, error is %s.",
								ip, podFullName, node, err)
						}
						return
					}
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
						ipCrd.Status.Phase = errMsg
						_, err = k8sManager.alphaClient.CiliumStaticIPs(ipCrd.Namespace).Update(context.TODO(), ipCrd, v1.UpdateOptions{})
						if err != nil {
							log.Errorf("delete statip ip failed, when delete ip: %s for pod: %s on node: %s, error is %s.",
								ip, podFullName, node, err)
						}
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

func transformToPool(obj interface{}) (interface{}, error) {
	switch concreteObj := obj.(type) {
	case *v2alpha1.CiliumPodIPPool:
		n := &v2alpha1.CiliumPodIPPool{
			TypeMeta: concreteObj.TypeMeta,
			ObjectMeta: v1.ObjectMeta{
				Name:            concreteObj.Name,
				ResourceVersion: concreteObj.ResourceVersion,
			},
			Spec: v2alpha1.IPPoolSpec{
				SubnetId: concreteObj.Spec.SubnetId,
				VPCId:    concreteObj.Spec.VPCId,
				CIDR:     concreteObj.Spec.CIDR,
			},
		}
		*concreteObj = v2alpha1.CiliumPodIPPool{}
		return n, nil
	case cache.DeletedFinalStateUnknown:
		p, ok := concreteObj.Obj.(*v2alpha1.CiliumPodIPPool)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &v2alpha1.CiliumPodIPPool{
				TypeMeta: p.TypeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name:            p.Name,
					ResourceVersion: p.ResourceVersion,
				},
				Spec: v2alpha1.IPPoolSpec{
					SubnetId: p.Spec.SubnetId,
					VPCId:    p.Spec.VPCId,
					CIDR:     p.Spec.CIDR,
				},
			},
		}
		// Small GC optimization
		*p = v2alpha1.CiliumPodIPPool{}
		return dfsu, nil
	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
	}
}

func updatePool(obj interface{}) {
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

func updateNode(obj interface{}) {
	key, _ := queueKeyFunc(obj)
	var retryCount int
loop:
	node, ok := k8sManager.nodeManager.nodes[key]
	if !ok && retryCount < 3 {
		<-time.After(1 * time.Second)
		retryCount++
		goto loop
	}
	if ok {
		err := k8sManager.nodeManager.SyncMultiPool(node)
		if err != nil {
			log.Error(err)
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
			log.Warnf("The creation of default pool has been ignored, due to subnet-id %s not found.", defaultSubnetID)
		}
	}
	log.Warnf("The creation of default pool has been ignored, due to no subnet-id set.")
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
