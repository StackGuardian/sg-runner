// Package metrics defines the scaler's Prometheus metrics.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const ns = "sg_runner_scaler"

// Metrics are the scaler's gauges and counters, on their own registry.
type Metrics struct {
	Registry *prometheus.Registry

	Queued              prometheus.Gauge
	ReservedPct         prometheus.Gauge
	FreePct             prometheus.Gauge
	Replicas            prometheus.Gauge
	Awake               prometheus.Gauge
	Parked              prometheus.Gauge
	Max                 prometheus.Gauge
	Stuck               prometheus.Gauge
	Unconnected         prometheus.Gauge
	Settling            prometheus.Gauge
	Leader              prometheus.Gauge
	ConsecutiveFailures prometheus.Gauge

	ScaleEvents   *prometheus.CounterVec
	Reaps         *prometheus.CounterVec
	StatusChanges *prometheus.CounterVec
	SGErrors      prometheus.Counter
	KubeErrors    prometheus.Counter
	LoopDuration  prometheus.Histogram
}

// New registers the metrics on a fresh registry.
func New() *Metrics {
	g := func(name, help string) prometheus.Gauge {
		return prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: name, Help: help})
	}
	m := &Metrics{
		Registry:            prometheus.NewRegistry(),
		Queued:              g("queued_workflows", "Workflows queued in the runner group."),
		ReservedPct:         g("reserved_percent", "Share of awake ACTIVE, connected runners' CPU or memory reserved (higher of the two)."),
		FreePct:             g("free_percent", "100 minus reserved_percent."),
		Replicas:            g("replicas", "Replicas of the runner StatefulSet after this loop."),
		Awake:               g("awake_runners", "Runners with a pod (ordinal below replicas) at the start of the loop."),
		Parked:              g("parked_runners", "Runners parked: a state PVC but no pod."),
		Max:                 g("max_runners", "Effective maximum: the lower of SCALER_MAX and MaxNumberOfRunners."),
		Stuck:               g("stuck", "1 while queued workflows fit no runner (stuck queue)."),
		Unconnected:         g("unconnected_runners", "Awake runners not connected to SG."),
		Settling:            g("settling_runners", "Awake runners not connected yet, within the settle timeout."),
		Leader:              g("leader", "1 while this replica holds the leader lease."),
		ConsecutiveFailures: g("consecutive_failures", "Loops failed in a row (SG or Kubernetes API errors)."),
		ScaleEvents: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "scale_events_total",
			Help: "Replica changes by direction (out, in)."}, []string{"direction"}),
		Reaps: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "reaps_total",
			Help: "Reap steps by result (started, succeeded, failed)."}, []string{"result"}),
		StatusChanges: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "runner_status_changes_total",
			Help: "Runner status changes through SG by reason and result."}, []string{"reason", "result"}),
		SGErrors: prometheus.NewCounter(prometheus.CounterOpts{Namespace: ns, Name: "sg_api_errors_total",
			Help: "Failed SG API calls."}),
		KubeErrors: prometheus.NewCounter(prometheus.CounterOpts{Namespace: ns, Name: "kube_api_errors_total",
			Help: "Failed Kubernetes API calls."}),
		LoopDuration: prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: ns, Name: "loop_duration_seconds",
			Help: "Duration of a scaling loop.", Buckets: prometheus.ExponentialBuckets(0.05, 2, 10)}),
	}
	m.Registry.MustRegister(
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.Queued, m.ReservedPct, m.FreePct, m.Replicas, m.Awake, m.Parked, m.Max, m.Stuck, m.Unconnected,
		m.Settling, m.Leader, m.ConsecutiveFailures,
		m.ScaleEvents, m.Reaps, m.StatusChanges, m.SGErrors, m.KubeErrors, m.LoopDuration,
	)
	for _, d := range []string{"out", "in"} {
		m.ScaleEvents.WithLabelValues(d)
	}
	for _, r := range []string{"started", "succeeded", "failed"} {
		m.Reaps.WithLabelValues(r)
	}
	return m
}

// Handler serves the registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{Registry: m.Registry})
}
