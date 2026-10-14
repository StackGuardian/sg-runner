package steps

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

// APIVersion is what GET /healthz reports.
const APIVersion = "v1"

// maxBody caps a request body: the env's 1 MB, JSON-escaped, with room.
const maxBody = 8 << 20

// recordTTL is how long the broker remembers a step after its pod is gone.
const recordTTL = time.Hour

// LogOpener streams a pod's logs.
type LogOpener func(ctx context.Context, namespace, pod string, opts *corev1.PodLogOptions) (io.ReadCloser, error)

// Server is the broker's API on top of the cluster.
type Server struct {
	Config Config
	Client kubernetes.Interface
	// Logs streams step logs (Client's when nil). Give it a client without
	// a request timeout: a followed stream lasts as long as the step.
	Logs LogOpener
	Log  *slog.Logger
	// Random makes step ids (crypto/rand when nil).
	Random io.Reader
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// StopPollInterval is how often the broker reads a stopped step's pod
	// until it's gone, for its exit code (250ms when 0).
	StopPollInterval time.Duration
	// PollInterval is how often a log request checks whether the container
	// started (1s when 0).
	PollInterval time.Duration

	idRE *regexp.Regexp

	mu      sync.Mutex
	steps   map[string]*stepRecord
	streams map[string]int
}

// stepRecord is what the broker remembers of a step besides its pod: a stop
// it was asked for, the final state, and the pod's deletion.
type stepRecord struct {
	at time.Time
	// stopped: a client asked for the stop; last is the latest state seen
	// since.
	stopped bool
	last    *State
	// following: a goroutine reads the stopped pod until it's gone.
	following bool
	// final is the terminal state a client got (or the GC went by): the
	// step's state for good, also once its pod is gone.
	final *State
	// servedAt is when a client first got final (zero when the GC set it):
	// the pod stays FINISHED_GRACE after.
	servedAt time.Time
	// deleting: one deletion of the pod and Secrets runs; deleted: done.
	deleting  bool
	deleted   bool
	deletedAt time.Time
	// secretsDeleted: the step's Secrets are gone.
	secretsDeleted bool
}

// recordLocked is a step's record, made when missing; s.mu is held.
func (s *Server) recordLocked(id string) *stepRecord {
	rec := s.steps[id]
	if rec == nil {
		rec = &stepRecord{at: s.now()}
		s.steps[id] = rec
	}
	return rec
}

// see keeps a stopped step's latest state, but never trades an exit seen for
// a state without one.
func (rec *stepRecord) see(st State) {
	if rec.last == nil || rec.last.State != StateExited || st.State == StateExited {
		rec.last = &st
	}
}

// NewServer returns a broker for a configuration.
func NewServer(cfg Config, client kubernetes.Interface, log *slog.Logger) *Server {
	return &Server{
		Config:  cfg,
		Client:  client,
		Log:     log,
		idRE:    cfg.idRE(),
		steps:   map[string]*stepRecord{},
		streams: map[string]int{},
	}
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler is the HTTP API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"api": APIVersion})
	})
	mux.HandleFunc("POST /v1/steps", s.create)
	mux.HandleFunc("GET /v1/steps/{id}", s.get)
	mux.HandleFunc("GET /v1/steps/{id}/logs", s.logs)
	mux.HandleFunc("POST /v1/steps/{id}/stop", s.stop)
	mux.HandleFunc("DELETE /v1/steps/{id}", s.delete)
	// Every error is JSON, unknown routes too.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, &Error{Status: http.StatusNotFound, Reason: ReasonNotFound, Message: "no route " + r.Method + " " + r.URL.Path})
	})
	return mux
}

// Listen listens on the unix socket path, replacing a stale socket file, and
// lets anyone who reaches the file connect.
func Listen(socketPath string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return nil, err
	}
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0o666); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes an *Error, anything else as a KubernetesError.
func writeError(w http.ResponseWriter, err error) {
	var e *Error
	if !errors.As(err, &e) {
		e = &Error{Status: http.StatusInternalServerError, Reason: ReasonKubernetesError, Message: err.Error()}
	}
	writeJSON(w, e.Status, e)
}

func kubeError(what string, err error) *Error {
	return &Error{Status: http.StatusInternalServerError, Reason: ReasonKubernetesError, Message: what + ": " + err.Error()}
}

func notFound(id string) *Error {
	return &Error{Status: http.StatusNotFound, Reason: ReasonNotFound, Message: "no step " + id}
}

// stepID is the request's id when it names one of this runner's steps: the
// API never touches other pods.
func (s *Server) stepID(r *http.Request) (string, error) {
	id := r.PathValue("id")
	if !s.idRE.MatchString(id) {
		return "", notFound(id)
	}
	return id, nil
}

func ignoreNotFound(err error) error {
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	var req Request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, badRequest(ReasonEnvTooLarge, "request body over %d bytes", maxBody))
			return
		}
		writeError(w, badRequest(ReasonInvalidRequest, "body: %v", err))
		return
	}
	if err := s.Config.Validate(&req); err != nil {
		writeError(w, err)
		return
	}
	random := s.Random
	if random == nil {
		random = rand.Reader
	}
	id, err := s.Config.NewID(random)
	if err != nil {
		writeError(w, fmt.Errorf("step id: %w", err))
		return
	}
	pull, err := s.Config.PullSecret(id, &req)
	if err != nil {
		writeError(w, badRequest(ReasonInvalidRequest, "registryAuth: %v", err))
		return
	}

	ctx := r.Context()
	secrets := s.Client.CoreV1().Secrets(s.Config.Namespace)
	var created []string
	// Secrets of a step that has no pod (else they go with the runner pod).
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		for _, name := range created {
			if err := ignoreNotFound(secrets.Delete(ctx, name, metav1.DeleteOptions{})); err != nil {
				s.Log.Warn("deleting a Secret of a step without a pod", "secret", name, "err", err)
			}
		}
	}
	if _, err := secrets.Create(ctx, s.Config.EnvSecret(id, &req), metav1.CreateOptions{}); err != nil {
		writeError(w, kubeError("create Secret "+EnvSecretName(id), err))
		return
	}
	created = append(created, EnvSecretName(id))
	if pull != nil {
		if _, err := secrets.Create(ctx, pull, metav1.CreateOptions{}); err != nil {
			cleanup()
			writeError(w, kubeError("create Secret "+PullSecretName(id), err))
			return
		}
		created = append(created, PullSecretName(id))
	}
	pod := s.Config.Pod(id, &req, pull != nil)
	if _, err := s.Client.CoreV1().Pods(s.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		cleanup()
		writeError(w, kubeError("create Pod "+id, err))
		return
	}
	s.Log.Info("step created", "id", id, "org", req.Org, "run", req.Run, "stepIdx", req.StepIdx,
		"name", req.Name, "image", req.Image)
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// state is a step's state: its final one once a client got that, a stopped
// step's last once its pod is gone.
func (s *Server) state(ctx context.Context, id string) (State, error) {
	if st, ok := s.final(id); ok {
		return st, nil
	}
	p, err := s.Client.CoreV1().Pods(s.Config.Namespace).Get(ctx, id, metav1.GetOptions{})
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.steps[id]
	if rec != nil && rec.final != nil {
		return *rec.final, nil
	}
	stopped := rec != nil && rec.stopped
	if apierrors.IsNotFound(err) {
		if stopped {
			return stoppedState(id, rec.last), nil
		}
		return State{}, notFound(id)
	}
	if err != nil {
		return State{}, kubeError("get Pod "+id, err)
	}
	st := s.Config.StepState(p, s.now(), stopped)
	if stopped {
		rec.see(st)
	}
	return st, nil
}

// final is a step's final state, if it has one.
func (s *Server) final(id string) (State, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec := s.steps[id]; rec != nil && rec.final != nil {
		return *rec.final, true
	}
	return State{}, false
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	id, err := s.stepID(r)
	if err != nil {
		writeError(w, err)
		return
	}
	st, err := s.state(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
	if st.Terminal() {
		s.served(id, st)
	}
}

// served records a terminal state a client got: the step's for good. Its pod
// and Secrets go FINISHED_GRACE later (a log stream may still be opening or
// reconnecting), or when its last log stream closes after that.
func (s *Server) served(id string, st State) {
	s.mu.Lock()
	rec := s.recordLocked(id)
	first := rec.final == nil
	if first {
		rec.final, rec.servedAt = &st, time.Now()
	}
	s.mu.Unlock()
	if !first {
		return
	}
	deleteNow := func() {
		if s.claimDeletion(id) {
			s.deleteFinal(id, "served")
		}
	}
	if s.Config.FinishedGrace <= 0 {
		go deleteNow()
		return
	}
	time.AfterFunc(s.Config.FinishedGrace, deleteNow)
}

// claimDeletion makes the caller a final step's only deleter, unless its
// grace hasn't passed, a log stream still reads it, or it's deleted already.
func (s *Server) claimDeletion(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.steps[id]
	if rec == nil || rec.final == nil || rec.deleting || rec.deleted || s.streams[id] > 0 ||
		!rec.servedAt.IsZero() && time.Since(rec.servedAt) < s.Config.FinishedGrace {
		return false
	}
	rec.deleting = true
	return true
}

// deleteFinal deletes a claimed step's pod and Secrets; a failure leaves it
// to the next GET, stream or sweep.
func (s *Server) deleteFinal(id, why string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := s.deleteStep(ctx, id)
	s.mu.Lock()
	rec := s.steps[id]
	rec.deleting = false
	if err == nil {
		rec.deleted, rec.deletedAt, rec.secretsDeleted = true, s.now(), true
	}
	final := *rec.final
	s.mu.Unlock()
	if err != nil {
		s.Log.Warn("deleting a finished step", "id", id, "why", why, "err", err)
		return
	}
	s.Log.Info("finished step deleted", "id", id, "why", why, "state", final.State, "reason", final.Reason)
}

func (s *Server) stop(w http.ResponseWriter, r *http.Request) {
	id, err := s.stepID(r)
	if err != nil {
		writeError(w, err)
		return
	}
	var body struct {
		GraceSeconds *int64 `json:"graceSeconds"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, badRequest(ReasonInvalidRequest, "body: %v", err))
		return
	}
	grace := int64(30)
	if body.GraceSeconds != nil {
		grace = *body.GraceSeconds
	}
	if grace < 0 {
		writeError(w, badRequest(ReasonInvalidRequest, "graceSeconds must not be negative"))
		return
	}
	// 0 would remove the pod object before the kubelet killed the container;
	// 1 still kills right away and keeps the pod (and the exit code) until then.
	if grace == 0 {
		grace = 1
	}

	ctx := r.Context()
	st, err := s.state(ctx, id)
	if err != nil {
		writeError(w, err)
		return
	}
	s.mu.Lock()
	rec := s.recordLocked(id)
	if !rec.stopped {
		rec.stopped, rec.last = true, &st
	}
	follow := !rec.following
	rec.following = true
	s.mu.Unlock()
	err = s.Client.CoreV1().Pods(s.Config.Namespace).Delete(ctx, id, metav1.DeleteOptions{GracePeriodSeconds: ptr.To(grace)})
	if err := ignoreNotFound(err); err != nil {
		s.mu.Lock()
		rec.following = false
		s.mu.Unlock()
		writeError(w, kubeError("delete Pod "+id, err))
		return
	}
	if follow {
		go s.followStop(id, time.Duration(grace)*time.Second+30*time.Second)
	}
	s.Log.Info("step stopped", "id", id, "graceSeconds", grace, "state", st.State)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id})
}

// followStop reads a stopped step's pod until it's gone (or for at most
// limit): the kubelet's final status, with the exit code, may last only a
// moment before the pod object goes.
func (s *Server) followStop(id string, limit time.Duration) {
	every := s.StopPollInterval
	if every <= 0 {
		every = 250 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	defer func() {
		s.mu.Lock()
		if rec := s.steps[id]; rec != nil {
			rec.following = false
		}
		s.mu.Unlock()
	}()
	for {
		p, err := s.Client.CoreV1().Pods(s.Config.Namespace).Get(ctx, id, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return
		}
		if err == nil {
			st := s.Config.StepState(p, s.now(), true)
			s.mu.Lock()
			if rec := s.steps[id]; rec != nil {
				rec.see(st)
			}
			s.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// deleteStep deletes a step's pod and Secrets; missing ones are fine.
func (s *Server) deleteStep(ctx context.Context, id string) error {
	err := s.Client.CoreV1().Pods(s.Config.Namespace).Delete(ctx, id, metav1.DeleteOptions{
		PropagationPolicy: ptr.To(metav1.DeletePropagationBackground),
	})
	if err := ignoreNotFound(err); err != nil {
		return kubeError("delete Pod "+id, err)
	}
	return s.deleteSecrets(ctx, id)
}

// deleteSecrets deletes a step's Secrets by name; missing ones are fine.
func (s *Server) deleteSecrets(ctx context.Context, id string) error {
	for _, name := range []string{EnvSecretName(id), PullSecretName(id)} {
		err := s.Client.CoreV1().Secrets(s.Config.Namespace).Delete(ctx, name, metav1.DeleteOptions{})
		if err := ignoreNotFound(err); err != nil {
			return kubeError("delete Secret "+name, err)
		}
	}
	return nil
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request) {
	id, err := s.stepID(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.deleteStep(r.Context(), id); err != nil {
		writeError(w, err)
		return
	}
	s.mu.Lock()
	if rec := s.steps[id]; rec != nil {
		rec.deleted, rec.deletedAt, rec.secretsDeleted = true, s.now(), true
	}
	s.mu.Unlock()
	s.Log.Info("step deleted", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) openStream(id string) {
	s.mu.Lock()
	s.streams[id]++
	s.mu.Unlock()
}

func (s *Server) closeStream(id string) {
	s.mu.Lock()
	if s.streams[id]--; s.streams[id] <= 0 {
		delete(s.streams, id)
	}
	s.mu.Unlock()
}

// streaming reports an open log stream of a step.
func (s *Server) streaming(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id] > 0
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	id, err := s.stepID(r)
	if err != nil {
		writeError(w, err)
		return
	}
	q := r.URL.Query()
	follow := q.Get("follow") == "1" || q.Get("follow") == "true"
	var since *time.Time
	if raw := q.Get("sinceTime"); raw != "" {
		t, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			writeError(w, badRequest(ReasonInvalidRequest, "sinceTime %q: want RFC3339Nano", raw))
			return
		}
		since = &t
	}
	ctx := r.Context()
	if _, err := s.state(ctx, id); err != nil {
		writeError(w, err)
		return
	}

	s.openStream(id)
	// The last stream of a step a client knows is done lets its pod go.
	defer func() {
		s.closeStream(id)
		if s.claimDeletion(id) {
			go s.deleteFinal(id, "logs closed")
		}
	}()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	if follow && !s.waitStarted(ctx, id) {
		return
	}

	opts := &corev1.PodLogOptions{Container: ContainerName, Follow: follow, Timestamps: true}
	if since != nil {
		opts.SinceTime = &metav1.Time{Time: *since}
	}
	open := s.Logs
	if open == nil {
		open = func(ctx context.Context, ns, pod string, opts *corev1.PodLogOptions) (io.ReadCloser, error) {
			return s.Client.CoreV1().Pods(ns).GetLogs(pod, opts).Stream(ctx)
		}
	}
	rc, err := open(ctx, s.Config.Namespace, id, opts)
	if err != nil {
		if ctx.Err() == nil {
			s.Log.Warn("opening step logs", "id", id, "err", err)
		}
		return
	}
	defer rc.Close()
	copyLines(w, flusher, rc, since)
}

// waitStarted waits until a step's container started or ended; false when it
// never will (failed, gone) or the client left.
func (s *Server) waitStarted(ctx context.Context, id string) bool {
	every := s.PollInterval
	if every <= 0 {
		every = time.Second
	}
	for {
		st, err := s.state(ctx, id)
		var e *Error
		switch {
		case errors.As(err, &e) && e.Status == http.StatusNotFound:
			return false
		case err != nil:
			s.Log.Warn("waiting for a step to start", "id", id, "err", err)
		case st.State == StateRunning || st.State == StateExited:
			return true
		case st.State == StateFailed:
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(every):
		}
	}
}

// copyLines copies log lines, flushing whenever it has caught up. The API
// server passes sinceTime on in whole seconds: lines before since are
// dropped here.
func copyLines(w io.Writer, flusher http.Flusher, r io.Reader, since *time.Time) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 && !before(line, since) {
			if _, werr := w.Write(line); werr != nil {
				return
			}
			if flusher != nil && br.Buffered() == 0 {
				flusher.Flush()
			}
		}
		if err != nil {
			if flusher != nil {
				flusher.Flush()
			}
			return
		}
	}
}

// before reports a line whose timestamp is before since.
func before(line []byte, since *time.Time) bool {
	if since == nil {
		return false
	}
	i := 0
	for i < len(line) && line[i] != ' ' {
		i++
	}
	t, err := time.Parse(time.RFC3339Nano, string(line[:i]))
	return err == nil && t.Before(*since)
}
