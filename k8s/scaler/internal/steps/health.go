package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/guard"
)

// Healthcheck checks that both sockets answer: GET /healthz on the API (api
// v1), Plugin.Activate on the guard (authz).
func Healthcheck(ctx context.Context, socketPath, guardSocket string, timeout time.Duration) error {
	client := func(sock string) *http.Client {
		return &http.Client{Timeout: timeout, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		}}
	}
	get := func(sock, method, url string, out any) error {
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", guard.MediaType)
		resp, err := client(sock).Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s %s: %s", method, url, resp.Status)
		}
		return json.NewDecoder(resp.Body).Decode(out)
	}

	var health struct{ API string }
	if err := get(socketPath, http.MethodGet, "http://steps/healthz", &health); err != nil {
		return fmt.Errorf("steps socket %s: %w", socketPath, err)
	}
	if health.API != APIVersion {
		return fmt.Errorf("steps socket %s: api %q, want %q", socketPath, health.API, APIVersion)
	}
	var m guard.Manifest
	if err := get(guardSocket, http.MethodPost, "http://guard/Plugin.Activate", &m); err != nil {
		return fmt.Errorf("guard socket %s: %w", guardSocket, err)
	}
	if !slices.Contains(m.Implements, "authz") {
		return fmt.Errorf("guard socket %s: implements %v, not authz", guardSocket, m.Implements)
	}
	return nil
}
