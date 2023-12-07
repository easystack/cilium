package staticip

import (
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"time"
)

type UpdateCSIPOption struct {
	status      *string
	eniId       *string
	portId      *string
	phase       *string
	nodeName    *string
	recycleTime *int
}

func NewUpdateCSIPOption() *UpdateCSIPOption {
	return &UpdateCSIPOption{}
}

func (o *UpdateCSIPOption) WithStatus(status string) *UpdateCSIPOption {
	o.status = &status
	return o
}

func (o *UpdateCSIPOption) WithPortId(portId string) *UpdateCSIPOption {
	o.portId = &portId
	return o
}

func (o *UpdateCSIPOption) WithPhase(phase string) *UpdateCSIPOption {
	o.phase = &phase
	return o
}
func (o *UpdateCSIPOption) WithENIId(eniId string) *UpdateCSIPOption {
	o.eniId = &eniId
	return o
}

func (o *UpdateCSIPOption) WithNodeName(nodeName string) *UpdateCSIPOption {
	o.nodeName = &nodeName
	return o
}

func (o *UpdateCSIPOption) WithRecycleTime(recycleTime int) *UpdateCSIPOption {
	o.recycleTime = &recycleTime
	return o
}
func (o *UpdateCSIPOption) BuildModifiedCsip(csip *v2alpha1.CiliumStaticIP) (*v2alpha1.CiliumStaticIP, error) {
	csip = csip.DeepCopy()

	if o.eniId != nil {
		csip.Spec.ENIId = *o.eniId
	}
	if o.status != nil {
		csip.Status.IPStatus = *o.status
	}
	if o.phase != nil {
		csip.Status.Phase = *o.phase
	}
	if o.portId != nil {
		csip.Spec.PortId = *o.portId
	}
	if o.recycleTime != nil {
		csip.Spec.RecycleTime = *o.recycleTime
	}
	if o.nodeName != nil {
		csip.Spec.NodeName = *o.nodeName
	}

	csip.Status.UpdateTime = v1.Time{
		Time: time.Now(),
	}

	return csip, nil
}

func (o *UpdateCSIPOption) BuildNewCsip(name string, namespace string, pool string, recycleTime int) *v2alpha1.CiliumStaticIP {
	ipCrd := &v2alpha1.CiliumStaticIP{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v2alpha1.CiliumStaticIPAPIVersion,
			Kind:       v2alpha1.CiliumStaticIPKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v2alpha1.StaticIPSpec{
			Pool:        pool,
			NodeName:    nodeTypes.GetName(),
			RecycleTime: recycleTime,
		},
		Status: v2alpha1.StaticIPStatus{},
	}

	return ipCrd
}
