// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package v2alpha1

import (
	"net/http"

	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	rest "k8s.io/client-go/rest"
)

type CiliumV2alpha1Interface interface {
	RESTClient() rest.Interface
	CiliumBGPPeeringPoliciesGetter
	CiliumCIDRGroupsGetter
	CiliumEndpointSlicesGetter
	CiliumL2AnnouncementPoliciesGetter
	CiliumLoadBalancerIPPoolsGetter
	CiliumNodeConfigsGetter
	CiliumPodIPPoolsGetter
	CiliumStaticIPsGetter
}

// CiliumV2alpha1Client is used to interact with features provided by the cilium.io group.
type CiliumV2alpha1Client struct {
	restClient rest.Interface
}

func (c *CiliumV2alpha1Client) CiliumBGPPeeringPolicies() CiliumBGPPeeringPolicyInterface {
	return newCiliumBGPPeeringPolicies(c)
}

func (c *CiliumV2alpha1Client) CiliumCIDRGroups() CiliumCIDRGroupInterface {
	return newCiliumCIDRGroups(c)
}

func (c *CiliumV2alpha1Client) CiliumEndpointSlices() CiliumEndpointSliceInterface {
	return newCiliumEndpointSlices(c)
}

func (c *CiliumV2alpha1Client) CiliumL2AnnouncementPolicies() CiliumL2AnnouncementPolicyInterface {
	return newCiliumL2AnnouncementPolicies(c)
}

func (c *CiliumV2alpha1Client) CiliumLoadBalancerIPPools() CiliumLoadBalancerIPPoolInterface {
	return newCiliumLoadBalancerIPPools(c)
}

func (c *CiliumV2alpha1Client) CiliumNodeConfigs(namespace string) CiliumNodeConfigInterface {
	return newCiliumNodeConfigs(c, namespace)
}

func (c *CiliumV2alpha1Client) CiliumPodIPPools() CiliumPodIPPoolInterface {
	return newCiliumPodIPPools(c)
}

func (c *CiliumV2alpha1Client) CiliumStaticIPs(namespace string) CiliumStaticIPInterface {
	return newCiliumStaticIPs(c, namespace)
}

// NewForConfig creates a new CiliumV2alpha1Client for the given config.
// NewForConfig is equivalent to NewForConfigAndClient(c, httpClient),
// where httpClient was generated with rest.HTTPClientFor(c).
func NewForConfig(c *rest.Config) (*CiliumV2alpha1Client, error) {
	config := *c
	if err := setConfigDefaults(&config); err != nil {
		return nil, err
	}
	httpClient, err := rest.HTTPClientFor(&config)
	if err != nil {
		return nil, err
	}
	return NewForConfigAndClient(&config, httpClient)
}

// NewForConfigAndClient creates a new CiliumV2alpha1Client for the given config and http client.
// Note the http client provided takes precedence over the configured transport values.
func NewForConfigAndClient(c *rest.Config, h *http.Client) (*CiliumV2alpha1Client, error) {
	config := *c
	if err := setConfigDefaults(&config); err != nil {
		return nil, err
	}
	client, err := rest.RESTClientForConfigAndClient(&config, h)
	if err != nil {
		return nil, err
	}
	return &CiliumV2alpha1Client{client}, nil
}

// NewForConfigOrDie creates a new CiliumV2alpha1Client for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *CiliumV2alpha1Client {
	client, err := NewForConfig(c)
	if err != nil {
		panic(err)
	}
	return client
}

// New creates a new CiliumV2alpha1Client for the given RESTClient.
func New(c rest.Interface) *CiliumV2alpha1Client {
	return &CiliumV2alpha1Client{c}
}

func setConfigDefaults(config *rest.Config) error {
	gv := v2alpha1.SchemeGroupVersion
	config.GroupVersion = &gv
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()

	if config.UserAgent == "" {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}

	return nil
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *CiliumV2alpha1Client) RESTClient() rest.Interface {
	if c == nil {
		return nil
	}
	return c.restClient
}
