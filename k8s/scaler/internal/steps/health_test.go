package steps

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/guard"
)

// serveOn serves h on a unix socket until the test ends.
func serveOn(t *testing.T, sock string, h http.Handler) {
	t.Helper()
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func TestHealthcheck(t *testing.T) {
	// macOS keeps unix socket paths under 104 bytes: a short temp dir.
	dir, err := os.MkdirTemp("", "hc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	stepsSock, guardSock := filepath.Join(dir, "steps.sock"), filepath.Join(dir, "guard.sock")
	ctx := context.Background()

	if err := Healthcheck(ctx, stepsSock, guardSock, time.Second); err == nil || !strings.Contains(err.Error(), "steps socket") {
		t.Errorf("nothing listening: %v", err)
	}
	serveOn(t, stepsSock, newHarness(t).s.Handler())
	if err := Healthcheck(ctx, stepsSock, guardSock, time.Second); err == nil || !strings.Contains(err.Error(), "guard socket") {
		t.Errorf("no guard: %v", err)
	}
	serveOn(t, guardSock, guard.Handler(slog.New(slog.NewJSONHandler(io.Discard, nil))))
	if err := Healthcheck(ctx, stepsSock, guardSock, time.Second); err != nil {
		t.Errorf("both up: %v", err)
	}
	// The sockets swapped: neither answers as expected.
	if err := Healthcheck(ctx, guardSock, stepsSock, time.Second); err == nil {
		t.Error("swapped sockets: want an error")
	}
}
