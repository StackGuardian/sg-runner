// Package sg is a minimal client for the StackGuardian runner group API,
// authenticated with the runner group's node token.
//
// The runner group response carries secrets (the group's runner token), so
// responses are decoded into structs holding only the fields the scaler
// needs, and neither bodies nor decoder messages end up in errors.
package sg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultBaseAPI is used when the credentials don't name one.
const DefaultBaseAPI = "https://api.app.stackguardian.io/api/v1"

// maxBody caps what is read from a response.
const maxBody = 16 << 20

// Credentials identify the runner group.
type Credentials struct {
	Token        string
	Organization string
	RunnerGroup  string
	BaseAPI      string
}

// LoadCredentials reads the credentials Secret mounted as one file per key.
func LoadCredentials(dir string) (Credentials, error) {
	read := func(key string, required bool) (string, error) {
		b, err := os.ReadFile(filepath.Join(dir, key))
		if err != nil {
			if !required && errors.Is(err, os.ErrNotExist) {
				return "", nil
			}
			return "", fmt.Errorf("read credential %s: %w", key, err)
		}
		v := strings.TrimSpace(string(b))
		if required && v == "" {
			return "", fmt.Errorf("credential %s is empty", key)
		}
		return v, nil
	}
	var c Credentials
	var err error
	if c.Token, err = read("SG_NODE_TOKEN", true); err != nil {
		return c, err
	}
	if c.Organization, err = read("SG_ORGANIZATION", true); err != nil {
		return c, err
	}
	if c.RunnerGroup, err = read("SG_RUNNER_GROUP", true); err != nil {
		return c, err
	}
	if c.BaseAPI, err = read("SG_BASE_API", false); err != nil {
		return c, err
	}
	if c.BaseAPI == "" {
		c.BaseAPI = DefaultBaseAPI
	}
	return c, nil
}

// Client calls the runner group API.
type Client struct {
	creds Credentials
	http  *http.Client
}

// New returns a client; a nil http.Client gets a 10s timeout.
func New(creds Credentials, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	creds.BaseAPI = strings.TrimRight(creds.BaseAPI, "/")
	return &Client{creds: creds, http: hc}
}

// Resource is a registered or remaining resource of a runner.
type Resource struct {
	Name         string  `json:"name"`
	IntegerValue float64 `json:"integerValue"`
}

// Instance is a runner (ECS container instance) of the group.
type Instance struct {
	RunnerID            string     `json:"runnerId"`
	Status              string     `json:"status"`
	AgentConnected      bool       `json:"agentConnected"`
	RunningTasksCount   int        `json:"runningTasksCount"`
	PendingTasksCount   int        `json:"pendingTasksCount"`
	RegisteredResources []Resource `json:"registeredResources"`
	RemainingResources  []Resource `json:"remainingResources"`
	InstanceDetails     []struct {
		ComputerName string `json:"ComputerName"`
	} `json:"instanceDetails"`
}

// ComputerName is the runner's host name: the pod's FQDN for k8s runners.
func (i Instance) ComputerName() string {
	if len(i.InstanceDetails) == 0 {
		return ""
	}
	return i.InstanceDetails[0].ComputerName
}

// ResourceValue returns the named resource's value from a list, 0 if absent.
func ResourceValue(list []Resource, name string) float64 {
	for _, r := range list {
		if r.Name == name {
			return r.IntegerValue
		}
	}
	return 0
}

// RunnerGroup is the part of the runner group the scaler uses.
type RunnerGroup struct {
	QueuedWorkflowsCount int        `json:"QueuedWorkflowsCount"`
	MaxNumberOfRunners   *int       `json:"MaxNumberOfRunners"`
	ContainerInstances   []Instance `json:"ContainerInstances"`
}

// APIError is a non-2xx answer. It never holds the response body.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
}

func (e *APIError) Error() string {
	return fmt.Sprintf("SG API %s %s: HTTP %d", e.Method, e.Path, e.StatusCode)
}

// RunnerGroup fetches the runner group with its active workflow counts.
func (c *Client) RunnerGroup(ctx context.Context) (*RunnerGroup, error) {
	body, err := c.do(ctx, http.MethodGet, "/?getActiveWorkflows=true", nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Msg *RunnerGroup `json:"msg"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		// Decoder messages can quote input: report only where it failed.
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return nil, fmt.Errorf("SG API GET runner group: invalid JSON at offset %d", se.Offset)
		}
		return nil, errors.New("SG API GET runner group: unexpected response shape")
	}
	if resp.Msg == nil {
		return nil, errors.New("SG API GET runner group: response has no msg")
	}
	return resp.Msg, nil
}

// SetRunnerStatus sets a runner ACTIVE or DRAINING through SG, which changes
// the ECS container instance state on its side.
func (c *Client) SetRunnerStatus(ctx context.Context, runnerID, status string) error {
	payload, err := json.Marshal(map[string]string{"Status": status, "RunnerId": runnerID})
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPost, "/runner_status/", payload)
	return err
}

func (c *Client) do(ctx context.Context, method, path string, payload []byte) ([]byte, error) {
	u := c.creds.BaseAPI + "/orgs/" + url.PathEscape(c.creds.Organization) +
		"/runnergroups/" + url.PathEscape(c.creds.RunnerGroup) + path
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, fmt.Errorf("SG API %s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "apikey "+c.creds.Token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("SG API %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("SG API %s %s: read response: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &APIError{Method: method, Path: path, StatusCode: resp.StatusCode}
	}
	return b, nil
}
