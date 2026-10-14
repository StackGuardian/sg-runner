// sg-runner-steps is the step broker: a container in the runner pod that runs
// each workflow step of the run controllers as a pod of its own. See
// k8s/docs/steps-api.md.
//
// `sg-runner-steps wait-drained` is its preStop hook: it returns once the
// runner's drain created DRAINED_MARKER.
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

	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/steps"
)

// markerPoll is how often the broker and wait-drained look for the marker.
const markerPoll = 2 * time.Second

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	klog.SetSlogLogger(log.With("source", "client-go"))
	run := serve
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
		case "wait-drained":
			run = waitDrained
		default:
			log.Error("unknown command: want serve or wait-drained", "command", os.Args[1])
			os.Exit(2)
		}
	}
	if err := run(log); err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func drained(marker string) bool {
	_, err := os.Stat(marker)
	return err == nil
}

// waitDrained returns once the drain marker exists; the pod's grace period
// bounds it. It reads DRAINED_MARKER alone so a configuration error can't
// cut a drain short.
func waitDrained(log *slog.Logger) error {
	marker := os.Getenv("DRAINED_MARKER")
	if marker == "" {
		marker = steps.DefaultDrainedMarker
	}
	for !drained(marker) {
		time.Sleep(markerPoll)
	}
	log.Info("runner drained", "marker", marker)
	return nil
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
	l, err := steps.Listen(cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.SocketPath, err)
	}
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(l) }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.RunGC(ctx, time.Minute)
	log.Info("serving", "socket", cfg.SocketPath, "runner", cfg.RunnerPodName, "node", cfg.NodeName)

	// Run controllers need the broker until their steps are done: SIGTERM
	// only counts once the runner's drain is.
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	tick := time.NewTicker(markerPoll)
	defer tick.Stop()
	terminating := false
wait:
	for {
		select {
		case err := <-served:
			return fmt.Errorf("serving: %w", err)
		case sig := <-sigs:
			if sig == syscall.SIGINT || drained(cfg.DrainedMarker) {
				break wait
			}
			if !terminating {
				log.Info("SIGTERM before the runner drained: serving until it did", "marker", cfg.DrainedMarker)
			}
			terminating = true
		case <-tick.C:
			if terminating && drained(cfg.DrainedMarker) {
				break wait
			}
		}
	}

	log.Info("shutting down")
	cancel()
	shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	if err := srv.Shutdown(shutdown); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
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
