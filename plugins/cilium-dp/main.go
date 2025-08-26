package main

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/deviceplugin"
	ciliumclientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	slimclientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	clientSet, resource, ctx, err := bootstrap()
	if err != nil {
		logrus.Fatal(err)
	}

	// Run plugin and informer concurrently
	errCh := make(chan error, 2)
	go func() { errCh <- runDevicePlugin(ctx, clientSet, resource) }()
	go func() { errCh <- runInformer(ctx, clientSet, resource) }()

	// Wait for the first error or stop signal
	if err := <-errCh; err != nil {
		logrus.Fatal(err)
	}
	logrus.Info("Server stopped...")
}

// runDevicePlugin starts the device plugin server.
func runDevicePlugin(ctx context.Context, clientSet *deviceplugin.ClientSet, resource *deviceplugin.Resource) error {
	plugin := deviceplugin.NewENIIPDevicePlugin(clientSet, resource)
	if err := plugin.Serve(ctx); err != nil {
		return fmt.Errorf("failed to serve device plugin: %w", err)
	}
	logrus.Infof("Device plugin server started")
	return nil
}

// runInformer starts the plugin informer.
func runInformer(ctx context.Context, clientSet *deviceplugin.ClientSet, resource *deviceplugin.Resource) error {
	informer := deviceplugin.NewPluginInformer(clientSet, resource)
	if err := informer.Run(ctx); err != nil {
		return fmt.Errorf("informer run error: %w", err)
	}
	logrus.Infof("Informer stopped gracefully")
	return nil
}

// bootstrap initializes all dependencies (ClientSet, Resource, Context).
func bootstrap() (*deviceplugin.ClientSet, *deviceplugin.Resource, context.Context, error) {
	clientSet, err := newClientSet()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	resource := &deviceplugin.Resource{
		LabelCh:      make(chan string),
		UpdateSignal: make(chan struct{}),
	}
	ctx := deviceplugin.SetupSignalContext()

	return clientSet, resource, ctx, nil
}

// newClientSet creates a ClientSet containing Slim, K8s, and Cilium clients.
func newClientSet() (*deviceplugin.ClientSet, error) {
	restConfig, err := deviceplugin.GetConfig()
	if err != nil {
		return nil, err
	}

	clientSet := &deviceplugin.ClientSet{}

	httpClient, err := rest.HTTPClientFor(restConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create k8s REST client: %w", err)
	}

	// Slim and K8s clients use protobuf marshalling
	restConfig.ContentConfig.ContentType = `application/vnd.kubernetes.protobuf`

	clientSet.SlimClient, err = slimclientset.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to create slim k8s client: %w", err)
	}

	clientSet.K8sClient, err = kubernetes.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to create k8s client: %w", err)
	}

	// The Cilium client uses JSON marshalling
	restConfig.ContentConfig.ContentType = `application/json`

	clientSet.CiliumClient, err = ciliumclientset.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to create cilium k8s client: %w", err)
	}
	return clientSet, nil
}
