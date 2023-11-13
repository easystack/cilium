// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumpodippool",path="ciliumpodippools",scope="Cluster",shortName={cpip}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion

// CiliumPodIPPool defines an IP pool that can be used for pooled IPAM (i.e. the multi-pool IPAM
// mode).
type CiliumPodIPPool struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec IPPoolSpec `json:"spec"`

	// +kubebuilder:validation:Optional
	Status IPPoolStatus `json:"status"`
}

// +kubebuilder:validation:XValidation:rule="!has(oldSelf.subnet-id) || has(self.subnet-id)", message="Value is required once set"
type IPPoolSpec struct {
	// IPv4 specifies the IPv4 CIDRs and mask sizes of the pool
	//
	// +kubebuilder:validation:Optional
	IPv4 *IPv4PoolSpec `json:"ipv4"`

	// IPv6 specifies the IPv6 CIDRs and mask sizes of the pool
	//
	// +kubebuilder:validation:Optional
	IPv6 *IPv6PoolSpec `json:"ipv6"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XValidation:rule=(self == oldSelf)
	SubnetId string `json:"subnet-id"`

	// +kubebuilder:validation:Optional
	CIDR string `json:"cidr"`

	// +kubebuilder:validation:Optional
	VPCId string `json:"vpc-id"`

	// +kubebuilder:validation:Optional
	Watermark string `json:"watermark"`

	// +kubebuilder:validation:Optional
	MaxFreePort int `json:"max-free-port"`

	// +kubebuilder:validation:Optional
	NodeMaxAboveWatermark int `json:"node-max-above-watermark"`

	// +kubebuilder:validation:Optional
	NodePreAllocate int `json:"node-pre-allocate"`
}

// IPPoolStatus describe the status of the nodes which uses the pool
type IPPoolStatus struct {
	// +kubebuilder:validation:Optional
	Active bool `json:"active"`

	// +kubebuilder:validation:Optional
	MaxPortsReached bool `json:"max-ports-reached"`

	// +kubebuilder:validation:Optional
	CurrentFreePort int `json:"current-free-port"`

	// Items is a list of CiliumPodIPPools.
	// +kubebuilder:validation:Optional
	Items map[string]ItemSpec `json:"items"`
}

// ItemSpec describe the status of the node which uses the pool
type ItemSpec struct {
	// +kubebuilder:validation:Optional
	Phase string `json:"phase"`
	// +kubebuilder:validation:Optional
	Status string `json:"status"`
}

type IPv4PoolSpec struct {
	// CIDRs is a list of IPv4 CIDRs that are part of the pool.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	CIDRs []PoolCIDR `json:"cidrs"`

	// MaskSize is the mask size of the pool.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=32
	// +kubebuilder:validation:ExclusiveMaximum=false
	MaskSize uint8 `json:"maskSize"`
}

type IPv6PoolSpec struct {
	// CIDRs is a list of IPv6 CIDRs that are part of the pool.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	CIDRs []PoolCIDR `json:"cidrs"`

	// MaskSize is the mask size of the pool.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=128
	// +kubebuilder:validation:ExclusiveMaximum=false
	MaskSize uint8 `json:"maskSize"`
}

// PoolCIDR is an IP pool CIDR.
//
// +kubebuilder:validation:Format=cidr
type PoolCIDR string

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumPodIPPoolList is a list of CiliumPodIPPool objects.
type CiliumPodIPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of CiliumPodIPPools.
	Items []CiliumPodIPPool `json:"items"`
}
