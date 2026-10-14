// sg-runner-steps is the step broker: a native sidecar of the runner pod that
// runs each workflow step of the run controllers as a pod of its own, and
// serves dockerd the sg-steps-guard authorization plugin, which refuses step
// containers in dockerd. See k8s/docs/steps-api.md.
//
// `sg-runner-steps healthcheck` is its startup and readiness probe: it exits
// 0 when both sockets answer.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/guard"
	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/steps"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	klog.SetSlogLogger(log.With("source", "client-go"))
	run := serve
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
		case "healthcheck":
			run = healthcheck
		default:
			log.Error("unknown command: want serve or healthcheck", "command", os.Args[1])
			os.Exit(2)
		}
	}
	if err := run(log); err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}

// healthcheck checks both sockets; it reads only their paths, so it works
// whatever else the configuration says.
func healthcheck(*slog.Logger) error {
	env := func(key, def string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return def
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return steps.Healthcheck(ctx, env("SOCKET_PATH", steps.DefaultSocketPath),
		env("GUARD_SOCKET", steps.DefaultGuardSocket), 2*time.Second)
}

func serve(log *slog.Logger) error {
	cfg, err := steps.LoadConfig(nil)
	if err != nil {
		return err
	}
	client, err := kubeClient(15 * time.Second)
	if err != nil {
		return err
	}
	// Followed log streams last as long as their step.
	streams, err := kubeClient(0)
	if err != nil {
		return err
	}

	s := steps.NewServer(cfg, client, log)
	s.Images = steps.NewRegistry()
	if cfg.BrokerImage == "" {
		log.Warn("BROKER_IMAGE is not set: steps run unwrapped, their exits 11 and 12 end the pod Failed")
	}
	s.Logs = func(ctx context.Context, ns, pod string, opts *corev1.PodLogOptions) (io.ReadCloser, error) {
		return streams.CoreV1().Pods(ns).GetLogs(pod, opts).Stream(ctx)
	}
	served := make(chan error, 2)
	var servers []*http.Server
	for _, sock := range []struct {
		path    string
		handler http.Handler
	}{
		{cfg.SocketPath, s.Handler()},
		{cfg.GuardSocket, guard.Handler(log)},
	} {
		l, err := steps.Listen(sock.path)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", sock.path, err)
		}
		srv := &http.Server{Handler: sock.handler, ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, srv)
		go func() { served <- srv.Serve(l) }()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.RunGC(ctx, time.Minute)
	log.Info("serving", "socket", cfg.SocketPath, "guard", cfg.GuardSocket, "runner", cfg.RunnerPodName, "node", cfg.NodeName)

	// A native sidecar gets SIGTERM only once the runner's containers (dockerd
	// and the run controllers in it) are gone.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	select {
	case err := <-served:
		return fmt.Errorf("serving: %w", err)
	case sig := <-sigs:
		log.Info("shutting down", "signal", sig.String())
	}

	cancel()
	shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdown); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	}
	return nil
}

// kubeClient connects in cluster, or with the usual kubeconfig out of
// cluster (development); timeout 0 is none.
func kubeClient(timeout time.Duration) (kubernetes.Interface, error) {
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		restCfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			return nil, err
		}
	}
	restCfg.Timeout = timeout
	restCfg.UserAgent = "sg-runner-steps"
	return kubernetes.NewForConfig(restCfg)
}
