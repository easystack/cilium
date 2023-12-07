// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	InUse             = "InUse"
	WaitingForAssign  = "WaitingForAssign"
	Idle              = "Idle"
	Assigned          = "Assigned"
	WaitingForRelease = "WaitingForRelease"
	Released          = "Released"
	Unbind            = "Unbind"
)

const (
	CiliumStaticIPAPIVersion = "cilium.io/v2alpha1"
	CiliumStaticIPKind       = "CiliumStaticIP"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:printcolumn:JSONPath=".spec.ip",description="Cilium static IP for this node",name="CiliumStaticIP",type=string
// +kubebuilder:printcolumn:JSONPath=".spec.node-name",description="Node for csip",name="Node",type=string
// +kubebuilder:printcolumn:JSONPath=".status.ip-status",description="IP status of the csip",name="Status",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",description="Time duration since creation of Ciliumnode",name="Age",type=date
// +kubebuilder:resource:categories={cilium},singular="ciliumstaticip",path="ciliumstaticips",shortName={csip}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion

// CiliumStaticIP defines
type CiliumStaticIP struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec StaticIPSpec `json:"spec"`

	Status StaticIPStatus `json:"status"`
}

type StaticIPSpec struct {
	// +kubebuilder:validation:Required
	IP string `json:"ip"`

	Pool string `json:"pool"`

	// +kubebuilder:validation:Optional
	NodeName string `json:"node-name"`

	// +kubebuilder:validation:Optional
	RecycleTime int `json:"recycle-time"`

	// +kubebuilder:validation:Optional
	ENIId string `json:"eni-id"`

	// +kubebuilder:validation:Optional
	PortId string `json:"port-id"`
}

type StaticIPStatus struct {
	// +kubebuilder:validation:Optional
	IPStatus string `json:"ip-status"`

	// +kubebuilder:validation:Optional
	UpdateTime v1.Time `json:"update-time"`

	// +kubebuilder:validation:Optional
	Phase string `json:"phase"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumStaticIPList is a list of StaticIP objects.
type CiliumStaticIPList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of StaticIPs.
	Items []CiliumStaticIP `json:"items"`
}
