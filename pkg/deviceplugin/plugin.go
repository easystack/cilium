package deviceplugin

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"time"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/fsnotify/fsnotify"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	period = time.Minute * 3

	ENIIPResourcePrefix = "openstack/eniip-"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "device-plugin")
)

var KubeletSocket = pluginapi.DevicePluginPath + "kubelet.sock"

type Resource struct {
	UpdateSignal chan struct{}
	Count        int
}

type ENIIPDevicePlugin struct {
	name     string
	endPoint string
	server   *grpc.Server
	res      *Resource
	ctx      context.Context
	listFunc func() int
	cancel   context.CancelFunc
}

// NewENIIPDevicePlugin creates a new ENIDevicePlugin.
func NewENIIPDevicePlugin(res *Resource, ctx context.Context, list func() int) *ENIIPDevicePlugin {
	c, cancelFunc := context.WithCancel(ctx)

	return &ENIIPDevicePlugin{
		res:      res,
		listFunc: list,
		cancel:   cancelFunc,
		ctx:      c,
	}
}

func (p *ENIIPDevicePlugin) Serve(project string) error {
	p.name = ENIIPResourcePrefix + project
	p.endPoint = path.Join(pluginapi.DevicePluginPath, fmt.Sprintf("eni-ip-%s.sock", project))
	err := p.start()
	log.Infof("Start device plugin for %v", p.name)

	if err != nil {
		log.Errorf("Device plugin start failed: %v", err)
		return fmt.Errorf("device plugin start failed: %v", err)
	}
	err = p.register()
	if err != nil {
		log.Errorf("Device plugin register failed: %v", err)
		return fmt.Errorf("device plugin register failed: %v", err)
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Errorf("Create watcher failed: %v", err)
		return err
	}
	err = watcher.Add(path.Clean(pluginapi.DevicePluginPath))
	if err != nil {
		log.Errorf("Watch kubelet failed")
		return err
	}
	go func() {
		log.Infof("Starting watch kubelet...")
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Name == KubeletSocket && event.Has(fsnotify.Create) {
					log.Infof(" %s created, restarting.", pluginapi.KubeletSocket)
					if p.server != nil {
						p.server.Stop()
					}

					if p.cancel != nil {
						p.cancel()
					}

					_ = os.Remove(p.endPoint)

					p.ctx, p.cancel = context.WithCancel(context.Background())
					_ = p.start()
					err = p.register()

					if err != nil {
						log.Errorf("Register failed after kubelet restart, %s", err)
					}

				} else if event.Name == "kubelet.sock" && event.Op&fsnotify.Remove == fsnotify.Remove {
					log.Infof("Kubelet stopped")
				}

			case err := <-watcher.Errors:
				if err != nil {
					log.Errorf("Watch kubelet failed: %s", err.Error())
				}
			case <-p.ctx.Done():
				break
			}
		}
	}()
	return nil
}

func (p *ENIIPDevicePlugin) start() error {
	if err := os.Remove(p.endPoint); err != nil && !os.IsNotExist(err) {
		return err
	}

	sock, err := net.Listen("unix", p.endPoint)
	if err != nil {
		return err
	}
	server := grpc.NewServer()

	pluginapi.RegisterDevicePluginServer(server, p)

	go func() {
		err := server.Serve(sock)
		if err != nil {
			log.Errorf("Failed to serve deviceplugin grpc server.")
		}
	}()

	conn, err := dailUnix(p.ctx, p.endPoint)
	if err != nil {
		return err
	}
	err = conn.Close()
	if err != nil {
		return err
	}

	return nil
}

func dailUnix(ctx context.Context, ep string) (*grpc.ClientConn, error) {
	conn, err := grpc.DialContext(ctx, ep,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", ep, time.Second*10)
		}),
	)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (p *ENIIPDevicePlugin) register() error {
	conn, err := dailUnix(p.ctx, KubeletSocket)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pluginapi.NewRegistrationClient(conn)
	_, err = client.Register(p.ctx, &pluginapi.RegisterRequest{
		Version:      pluginapi.Version,
		Endpoint:     path.Base(p.endPoint),
		ResourceName: p.name,
	})

	if err != nil {
		return err
	}

	return nil
}

// GetDevicePluginOptions returns options that ENI devices support.
func (p *ENIIPDevicePlugin) GetDevicePluginOptions(_ context.Context, _ *pluginapi.Empty) (*pluginapi.DevicePluginOptions, error) {
	return &pluginapi.DevicePluginOptions{}, nil
}

// ListAndWatch returns ENI devices list.
func (p *ENIIPDevicePlugin) ListAndWatch(_ *pluginapi.Empty, stream pluginapi.DevicePlugin_ListAndWatchServer) error {
	count := p.listFunc()

	sendResponse := func(count int, s pluginapi.DevicePlugin_ListAndWatchServer) error {
		enis := make([]*pluginapi.Device, count)
		for i := 0; i < count; i++ {
			enis[i] = &pluginapi.Device{
				ID:     fmt.Sprintf("%v-%d", p.name, i),
				Health: pluginapi.Healthy,
			}
		}

		resp := &pluginapi.ListAndWatchResponse{
			Devices: enis,
		}
		err := stream.Send(resp)
		log.Infof("Report resources: %v of %v", p.name, count)
		if err != nil {
			log.Errorf("Send devices error: %v", err)
			return err
		}
		return nil
	}

	if err := sendResponse(count, stream); err != nil {
		return err
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			count = p.listFunc()
			log.Infof("Device-plugin listFunc called, count: %d", count)
			err := sendResponse(count, stream)
			if err != nil {
				return err
			}
		// Send	new list when resource count changed
		case <-p.res.UpdateSignal:
			count = p.listFunc()

			log.Infof("Device-plugin updateSignal activated, count: %d", count)
			err := sendResponse(count, stream)
			if err != nil {
				return err
			}
		case <-p.ctx.Done():
			return nil
		}
	}
}

// Allocate does nothing, here we only return a void response.
func (p *ENIIPDevicePlugin) Allocate(_ context.Context, request *pluginapi.AllocateRequest) (*pluginapi.AllocateResponse, error) {
	resp := pluginapi.AllocateResponse{
		ContainerResponses: []*pluginapi.ContainerAllocateResponse{},
	}

	for range request.GetContainerRequests() {
		resp.ContainerResponses = append(resp.ContainerResponses,
			&pluginapi.ContainerAllocateResponse{},
		)
	}

	return &resp, nil
}

// PreStartContainer is not supported by this plugin.
func (p *ENIIPDevicePlugin) PreStartContainer(_ context.Context, _ *pluginapi.PreStartContainerRequest) (*pluginapi.PreStartContainerResponse, error) {
	return &pluginapi.PreStartContainerResponse{}, nil
}

// GetPreferredAllocation is not supported by this plugin.
func (p *ENIIPDevicePlugin) GetPreferredAllocation(_ context.Context, _ *pluginapi.PreferredAllocationRequest) (*pluginapi.PreferredAllocationResponse, error) {
	return &pluginapi.PreferredAllocationResponse{}, nil
}
