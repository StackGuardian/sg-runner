// sg-runner-scaler sizes the sg-runner StatefulSet from the runner group's
// state in StackGuardian, parks idle runners and deregisters runners parked
// for too long. See k8s/README.md, "Autoscaling".
//
// `sg-runner-scaler teardown` instead deregisters every runner and deletes
// their PVCs: the Helm chart's pre-delete hook, so `helm uninstall` leaves
// nothing behind.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"

	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/config"
	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/controller"
	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/kube"
	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/metrics"
	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/sg"
	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/teardown"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	klog.SetSlogLogger(log.With("source", "client-go"))
	run := run
	if len(os.Args) > 1 && os.Args[1] == "teardown" {
		run = runTeardown
	}
	if err := run(log); err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load(nil)
	if err != nil {
		return err
	}
	if cfg.MinRaised {
		log.Warn("SCALER_MIN raised to 1: SG pauses workflows without an ACTIVE runner", "given", cfg.MinGiven)
	}
	creds, err := sg.LoadCredentials(cfg.CredentialsDir)
	if err != nil {
		return err
	}

	client, err := kubeClient()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	m := metrics.New()
	broadcaster := record.NewBroadcaster(record.WithContext(ctx))
	broadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: client.CoreV1().Events(cfg.Namespace)})
	defer broadcaster.Shutdown()
	recorder := broadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "sg-runner-scaler"})

	k := kube.New(client, cfg.Namespace, cfg.StatefulSet, cfg.Image, cfg.CredentialsSecret, cfg.ConfigMap)
	k.ReapPod = cfg.ReapPod
	k.NudgeImage = cfg.NudgeImage
	ctrl := &controller.Controller{
		Config:   cfg.Rules,
		Interval: cfg.Interval,
		SG:       sg.New(creds, nil),
		Kube:     k,
		Events:   recorder,
		Metrics:  m,
		Log:      log,
		Nudge:    cfg.Nudge,
	}
	ctrl.NudgeCooldown = cfg.NudgeCooldown

	var leading atomic.Bool
	srv := serve(cfg, m, ctrl, &leading, log)
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	lead := func(ctx context.Context) {
		leading.Store(true)
		m.Leader.Set(1)
		_ = ctrl.Run(ctx)
	}
	if !cfg.LeaderElect {
		lead(ctx)
		return nil
	}

	id, err := identity()
	if err != nil {
		return err
	}
	lock := &resourcelock.LeaseLock{
		LeaseMeta:  metav1.ObjectMeta{Name: cfg.StatefulSet + "-scaler", Namespace: cfg.Namespace},
		Client:     client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{Identity: id},
	}
	log.Info("waiting for the leader lease", "lease", lock.LeaseMeta.Name, "identity", id)
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		Name:            lock.LeaseMeta.Name,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				log.Info("leading", "identity", id)
				lead(ctx)
			},
			OnStoppedLeading: func() {
				leading.Store(false)
				m.Leader.Set(0)
				log.Info("stopped leading", "identity", id)
			},
			OnNewLeader: func(current string) {
				if current != id {
					log.Info("following", "leader", current)
				}
			},
		},
	})
	if ctx.Err() == nil {
		// Lost the lease without being asked to stop: restart clean.
		return errors.New("lost the leader lease")
	}
	return nil
}

// runTeardown is the pre-delete hook: deregister every runner, delete PVCs.
// It runs until done or until the Job's activeDeadlineSeconds stops it.
func runTeardown(log *slog.Logger) error {
	cfg, err := config.Load(nil)
	if err != nil {
		return err
	}
	client, err := kubeClient()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	k := kube.New(client, cfg.Namespace, cfg.StatefulSet, cfg.Image, cfg.CredentialsSecret, cfg.ConfigMap)
	k.ReapPod = cfg.ReapPod
	td := &teardown.Teardown{
		Kube:             k,
		ScalerDeployment: os.Getenv("TEARDOWN_SCALER_DEPLOYMENT"),
		ScalerSelector:   os.Getenv("TEARDOWN_SCALER_SELECTOR"),
		RunnerSelector:   os.Getenv("TEARDOWN_RUNNER_SELECTOR"),
		Log:              log,
	}
	if td.RunnerSelector == "" || (td.ScalerDeployment != "" && td.ScalerSelector == "") {
		return errors.New("teardown needs TEARDOWN_RUNNER_SELECTOR, and TEARDOWN_SCALER_SELECTOR with TEARDOWN_SCALER_DEPLOYMENT")
	}
	return td.Run(ctx)
}

// kubeClient connects in cluster, or with the usual kubeconfig out of
// cluster (development).
func kubeClient() (kubernetes.Interface, error) {
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		restCfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			return nil, err
		}
	}
	restCfg.Timeout = 15 * time.Second
	restCfg.UserAgent = "sg-runner-scaler"
	return kubernetes.NewForConfig(restCfg)
}

func identity() (string, error) {
	host, err := os.Hostname()
	if err != nil {
		return "", err
	}
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return host + "_" + hex.EncodeToString(b), nil
}

// serve exposes /metrics, /healthz and /readyz. Not leading is healthy and
// ready (a standby); a leader whose loop stopped running is not healthy.
func serve(cfg config.Config, m *metrics.Metrics, ctrl *controller.Controller, leading *atomic.Bool, log *slog.Logger) *http.Server {
	stale := 2*controller.DefaultMaxBackoff + cfg.Interval + time.Minute
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if leading.Load() {
			if last := ctrl.LastLoop(); !last.IsZero() && time.Since(last) > stale {
				http.Error(w, "scaling loop stalled", http.StatusServiceUnavailable)
				return
			}
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	srv := &http.Server{Addr: cfg.MetricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server", "err", err)
			os.Exit(1)
		}
	}()
	return srv
}
