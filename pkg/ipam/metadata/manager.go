// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"context"
	"fmt"
	v1 "k8s.io/api/core/v1"
	"strconv"
	"strings"
	"time"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/hive"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-metadata-manager")
)

const (
	// defaultCSIPRetainTime represent default retention time of CSIP, the value is 100 year.
	defaultCSIPRetainTime = int(time.Hour * 24 * 365 * 100 / time.Second)
)

type ManagerStoppedError struct{}

func (m *ManagerStoppedError) Error() string {
	return "ipam-metadata-manager has been stopped"
}

type ResourceNotFound struct {
	Resource  string
	Name      string
	Namespace string
}

func (r *ResourceNotFound) Error() string {
	name := r.Name
	if r.Namespace != "" {
		name = r.Namespace + "/" + r.Name
	}
	return fmt.Sprintf("resource %s %q not found", r.Resource, name)
}

func (r *ResourceNotFound) Is(target error) bool {
	targetErr, ok := target.(*ResourceNotFound)
	if !ok {
		return false
	}
	if r != nil && targetErr.Resource != "" {
		return r.Resource == targetErr.Resource
	}
	return true
}

type Manager struct {
	namespaceResource  resource.Resource[*slim_core_v1.Namespace]
	namespaceStore     resource.Store[*slim_core_v1.Namespace]
	podResource        k8s.LocalPodResource
	podStore           resource.Store[*slim_core_v1.Pod]
	nodeResource       k8s.LocalNodeResource
	projectLabelGetter utils.NodeLabelForProjectConfiguration
}

func (m *Manager) Start(ctx hive.HookContext) (err error) {
	m.namespaceStore, err = m.namespaceResource.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to obtain namespace store: %w", err)
	}

	m.podStore, err = m.podResource.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to obtain pod store: %w", err)
	}

	return nil
}

func (m *Manager) Stop(ctx hive.HookContext) error {
	m.namespaceStore = nil
	m.podStore = nil
	return nil
}

func splitK8sPodName(owner string) (namespace, name string, ok bool) {
	// Require namespace/name format
	namespace, name, ok = strings.Cut(owner, "/")
	if !ok {
		return "", "", false
	}
	// Check if components are a valid namespace name and pod name
	if validation.IsDNS1123Subdomain(namespace) != nil ||
		validation.IsDNS1123Subdomain(name) != nil {
		return "", "", false
	}
	return namespace, name, true
}

func (m *Manager) GetProjectFromNodeLabel() (string, error) {
	store, err := m.nodeResource.Store(context.TODO())
	if err != nil {
		return "", err
	}
	node, exists, err := store.GetByKey(resource.Key{Name: nodeTypes.GetName()})
	if err != nil {
		return "", err
	}
	if !exists {
		return "", k8sErrors.NewNotFound(schema.GroupResource{
			Group:    "core",
			Resource: "Node",
		}, nodeTypes.GetName())
	}

	if project, ok := node.Labels[m.projectLabelGetter.GetNodeLabelForProject()]; ok {
		return project, nil
	}

	// project label not found, back to switch default
	return "", nil
}

func (m *Manager) GetIPPoolForPod(owner, resourceName string) (pool string, err error) {
	if m.namespaceStore == nil || m.podStore == nil {
		return "", &ManagerStoppedError{}
	}

	namespace, name, ok := splitK8sPodName(owner)
	if !ok {
		log.WithField("owner", owner).
			Debug("IPAM metadata request for invalid pod name, falling back to default pool")
		return ipamOption.PoolDefault, nil
	}

	// Check annotation on pod
	pod, ok, err := m.podStore.GetByKey(resource.Key{
		Name:      name,
		Namespace: namespace,
	})
	if err != nil {
		return "", fmt.Errorf("failed to lookup pod %q: %w", namespace+"/"+name, err)
	} else if !ok {
		return "", &ResourceNotFound{Resource: "Pod", Namespace: namespace, Name: name}
	}

	log.Infof("Device_plugin output %v", pod.Spec.Containers[0].Resources)

	if ipPool, hasAnnotation := pod.Annotations[annotation.IPAMPoolKey]; hasAnnotation {
		return ipPool, nil
	}

	if _, ok := pod.Spec.Containers[0].Resources.Requests[v1.ResourceName(resourceName)]; !ok {
		// device-plugin resource not injected, switch default
		return ipamOption.PoolDefault, nil
	}

	// Fallback to not specified
	return ipamOption.PoolNotSpecified, nil
}

func (m *Manager) GetIPPolicyForPod(owner string) (string, int, error) {
	if m.namespaceStore == nil || m.podStore == nil {
		return "", 0, &ManagerStoppedError{}
	}

	namespace, name, ok := splitK8sPodName(owner)
	if !ok {
		log.WithField("owner", owner).
			Debug("IPAM metadata request for invalid pod name")
		return "", 0, nil
	}

	// Check annotation on pod
	pod, ok, err := m.podStore.GetByKey(resource.Key{
		Name:      name,
		Namespace: namespace,
	})
	if err != nil {
		return "", 0, fmt.Errorf("failed to lookup pod %q: %w", namespace+"/"+name, err)
	} else if !ok {
		return "", 0, &ResourceNotFound{Resource: "Pod", Namespace: namespace, Name: name}
	} else {
		isJudgeNeededPod := false
		if pod.OwnerReferences == nil {
			isJudgeNeededPod = true
		} else if len(pod.OwnerReferences) > 0 {
			for _, o := range pod.OwnerReferences {
				if o.Kind == "StatefulSet" {
					isJudgeNeededPod = true
					break
				}
			}
		}
		if isJudgeNeededPod {
			if policy, hasAnnotation := pod.Annotations[annotation.IPAMIPPolicyRetainKey]; hasAnnotation {
				if t, hasAnnotation := pod.Annotations[annotation.IPAMIPPolicyRetainTime]; hasAnnotation {
					time, err := strconv.Atoi(t)
					if err != nil {
						return policy, defaultCSIPRetainTime, nil
					}
					return policy, time, nil
				} else {
					return policy, defaultCSIPRetainTime, nil
				}
			}
		}
	}

	return "", 0, nil
}
func (m *Manager) GetLocalPods() ([]*slim_core_v1.Pod, error) {

	if m.podStore == nil {
		return nil, fmt.Errorf("pod store uninitialized")
	}
	values := m.podStore.List()

	return values, nil

}
