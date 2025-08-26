package deviceplugin

import (
	"fmt"
	"sync"

	cilium_clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	slim_client "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	config     *rest.Config
	configOnce sync.Once
)

// GetConfig initializes and returns the in-cluster Kubernetes REST configuration.
// It ensures that the configuration is initialized only once using sync.Once.
func GetConfig() (*rest.Config, error) {
	var err error
	configOnce.Do(func() {
		// Get the in-cluster configuration
		config, err = rest.InClusterConfig()
		if err != nil {
			err = fmt.Errorf("failed to generate kubernetes client config: %v", err)
			return
		}
	})
	return config, err
}

type ClientSet struct {
	K8sClient    *kubernetes.Clientset
	SlimClient   *slim_client.Clientset
	CiliumClient *cilium_clientset.Clientset
}
