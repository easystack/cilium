// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

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

	k8sManager = extraManager{}

	creationDefaultPoolOnce sync.Once
)

const (
	defaultGCTime                  = time.Second * 10
	defaultAssignTimeOut           = time.Minute * 4
	defaultInUseTimeOut            = time.Minute * 2
	defaultWaitingForAssignTimeOut = time.Minute * 1

	DefaultMaxCreatePort     = 1024
	DefaultCPIPWatermark     = "1"
	DefaultPreallocate       = 3
	DefaultMaxAboveWaterMark = 10
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
	apiReady    bool
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
func (m extraManager) updateStaticIP(ipCrd *v2alpha1.CiliumStaticIP) {

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
					errMsg := fmt.Sprintf("allocate static ip: %v for pod %v failed: %s.", ip, podFullName, err)
					k8sManager.UpdateCiliumStaticIP(ipCrd, v2alpha1.WaitingForAssign, errMsg, "", "")
					return
				}
				k8sManager.UpdateCiliumStaticIP(ipCrd, v2alpha1.Assigned, "", eniID, portId)
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
			k8sManager.UpdateCiliumStaticIP(ipCrd, v2alpha1.Idle, err.Error(), "", "")
		} else {
			if n, ok := k8sManager.nodeManager.nodes[node]; ok {
				err = n.Ops().UnbindStaticIP(context.TODO(), ipCrd.Spec.IP, ipPool.Spec.VPCId)
				if err != nil {
					log.Errorf("unbind static ip %s failed, error is %s", ip, err)
					k8sManager.UpdateCiliumStaticIP(ipCrd, v2alpha1.Idle, err.Error(), "", "")
					return
				} else {
					k8sManager.UpdateCiliumStaticIP(ipCrd, v2alpha1.Unbind, "", "", "")
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
					err := n.Ops().ReleaseStaticIP(ip, pool, ipCrd.Spec.PortId)
					if err != nil {
						errMsg := fmt.Sprintf("delete static ip: %v for pod %v failed: %s.", ip, podFullName, err)
						k8sManager.UpdateCiliumStaticIP(ipCrd, v2alpha1.WaitingForRelease, errMsg, "", "")
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

func (extraManager) UpdateCiliumStaticIP(csip *v2alpha1.CiliumStaticIP, status, phase string, eniId string, portId string) {
	now := time.Now()
	podFullName := csip.Namespace + "/" + csip.Name

	csip = csip.DeepCopy()
	if status == v2alpha1.Assigned {
		csip.Spec.ENIId = eniId
		csip.Spec.PortId = portId
	}

	if status == v2alpha1.Unbind || status == v2alpha1.WaitingForRelease {
		csip.Spec.ENIId = ""
	}

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
