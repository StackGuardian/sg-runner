package steps

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// testRegistry is an in-memory registry that counts requests by path and can
// require basic auth.
type testRegistry struct {
	srv  *httptest.Server
	host string

	mu       sync.Mutex
	requests []string
	user     string
	password string
}

func newTestRegistry(t *testing.T) *testRegistry {
	r := &testRegistry{}
	reg := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.requests = append(r.requests, req.Method+" "+req.URL.Path)
		user, password := r.user, r.password
		r.mu.Unlock()
		if user != "" {
			if u, p, ok := req.BasicAuth(); !ok || u != user || p != password {
				w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		reg.ServeHTTP(w, req)
	}))
	t.Cleanup(r.srv.Close)
	r.host = strings.TrimPrefix(r.srv.URL, "http://")
	return r
}

func (r *testRegistry) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.requests...)
}

// image is a random image with a layer, and entrypoint and cmd.
func image(t *testing.T, entrypoint, cmd []string, platform *v1.Platform) v1.Image {
	img, err := random.Image(1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.Config.Entrypoint, cf.Config.Cmd = entrypoint, cmd
	if platform != nil {
		cf.OS, cf.Architecture = platform.OS, platform.Architecture
	}
	img, err = mutate.ConfigFile(img, cf)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func (r *testRegistry) push(t *testing.T, ref string, img v1.Image) {
	t.Helper()
	tag, err := name.ParseReference(r.host + "/" + ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(tag, img); err != nil {
		t.Fatal(err)
	}
}

func newLookup(platform v1.Platform) *Registry {
	r := NewRegistry()
	r.Platform = platform
	return r
}

var amd64, arm64 = v1.Platform{OS: "linux", Architecture: "amd64"}, v1.Platform{OS: "linux", Architecture: "arm64"}

func TestLookupReadsOnlyManifestAndConfig(t *testing.T) {
	reg := newTestRegistry(t)
	img := image(t, []string{"/entry"}, []string{"run", "--x"}, nil)
	reg.push(t, "team/step:1", img)
	layers, _ := img.Layers()

	before := len(reg.seen())
	got, err := newLookup(amd64).Lookup(context.Background(), reg.host+"/team/step:1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, ImageConfig{Entrypoint: []string{"/entry"}, Cmd: []string{"run", "--x"}}) {
		t.Errorf("config %+v", got)
	}
	cfgDigest, _ := img.ConfigName()
	for _, req := range reg.seen()[before:] {
		for _, l := range layers {
			d, _ := l.Digest()
			if strings.Contains(req, d.String()) {
				t.Errorf("fetched a layer: %s", req)
			}
		}
		if strings.Contains(req, "/blobs/") && !strings.Contains(req, cfgDigest.String()) {
			t.Errorf("fetched another blob: %s", req)
		}
	}
}

func TestLookupPicksThePlatform(t *testing.T) {
	reg := newTestRegistry(t)
	add := func(idx v1.ImageIndex, p v1.Platform, entry string) v1.ImageIndex {
		return mutate.AppendManifests(idx, mutate.IndexAddendum{Add: image(t, []string{entry}, nil, &p),
			Descriptor: v1.Descriptor{Platform: &p}})
	}
	// Attestations come as "unknown/unknown" entries.
	unknown := v1.Platform{OS: "unknown", Architecture: "unknown"}
	multi := add(add(add(empty.Index, unknown, "/attestation"), amd64, "/amd64"), arm64, "/arm64")
	armOnly := add(add(empty.Index, unknown, "/attestation"), arm64, "/arm64")
	s390 := v1.Platform{OS: "linux", Architecture: "s390x"}
	others := add(add(empty.Index, unknown, "/attestation"), s390, "/s390x")
	windows := add(empty.Index, v1.Platform{OS: "windows", Architecture: "amd64"}, "/windows")
	for ref, idx := range map[string]v1.ImageIndex{"multi:1": multi, "arm:1": armOnly, "others:1": others, "windows:1": windows} {
		tag, _ := name.ParseReference(reg.host + "/" + ref)
		if err := remote.WriteIndex(tag, idx); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		platform v1.Platform
		ref      string
		want     string
	}{
		{arm64, "multi:1", "/arm64"},
		{amd64, "multi:1", "/amd64"},
		{v1.Platform{OS: "linux", Architecture: "riscv64"}, "multi:1", "/amd64"},
		{amd64, "arm:1", "/arm64"},
		{amd64, "others:1", "/s390x"},
		{amd64, "windows:1", ""},
	} {
		got, err := newLookup(c.platform).Lookup(context.Background(), reg.host+"/"+c.ref, nil)
		if c.want == "" {
			if err == nil {
				t.Errorf("%s on %s: want an error, got %+v", c.ref, c.platform.Architecture, got)
			}
			continue
		}
		if err != nil || len(got.Entrypoint) != 1 || got.Entrypoint[0] != c.want {
			t.Errorf("%s on %s: %+v %v, want %s", c.ref, c.platform.Architecture, got, err, c.want)
		}
	}
}

func TestLookupAuth(t *testing.T) {
	reg := newTestRegistry(t)
	reg.push(t, "private:1", image(t, []string{"/entry"}, nil, nil))
	reg.mu.Lock()
	reg.user, reg.password = "u", "p"
	reg.mu.Unlock()
	ref := reg.host + "/private:1"

	if _, err := newLookup(amd64).Lookup(context.Background(), ref, nil); err == nil {
		t.Error("anonymous: want an error")
	}
	// Credentials of another registry stay out of it.
	other := &RegistryAuth{Registry: "registry.example.com", Username: "u", Password: "p"}
	if _, err := newLookup(amd64).Lookup(context.Background(), ref, other); err == nil {
		t.Error("another registry's auth: want an error")
	}
	for _, registry := range []string{reg.host, "http://" + reg.host + "/v2/"} {
		auth := &RegistryAuth{Registry: registry, Username: "u", Password: "p"}
		got, err := newLookup(amd64).Lookup(context.Background(), ref, auth)
		if err != nil || got.Entrypoint[0] != "/entry" {
			t.Errorf("auth for %s: %+v %v", registry, got, err)
		}
	}
}

func TestLookupCaches(t *testing.T) {
	reg := newTestRegistry(t)
	reg.push(t, "step:1", image(t, nil, []string{"sh"}, nil))
	l := newLookup(amd64)
	now := t0
	l.Now = func() time.Time { return now }
	ref := reg.host + "/step:1"

	lookups := func() int {
		n := 0
		for _, r := range reg.seen() {
			if strings.Contains(r, "/manifests/") {
				n++
			}
		}
		return n
	}
	start := lookups()
	for _, at := range []time.Duration{0, time.Minute, 9 * time.Minute} {
		now = t0.Add(at)
		if got, err := l.Lookup(context.Background(), ref, nil); err != nil || got.Cmd[0] != "sh" {
			t.Fatalf("lookup at %s: %+v %v", at, got, err)
		}
	}
	if n := lookups() - start; n != 1 {
		t.Errorf("%d manifest requests within 10 minutes, want 1", n)
	}
	now = t0.Add(11 * time.Minute)
	if _, err := l.Lookup(context.Background(), ref, nil); err != nil {
		t.Fatal(err)
	}
	if n := lookups() - start; n != 2 {
		t.Errorf("%d manifest requests after the TTL, want 2", n)
	}
	// Failures aren't cached.
	if _, err := l.Lookup(context.Background(), reg.host+"/missing:1", nil); err == nil {
		t.Error("missing image: want an error")
	}
	if _, ok := l.cache[reg.host+"/missing:1"]; ok {
		t.Error("a failure got cached")
	}
}

func TestLookupTimeout(t *testing.T) {
	hang := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-hang }))
	defer srv.Close()
	defer close(hang)
	l := newLookup(amd64)
	l.Timeout = 100 * time.Millisecond
	start := time.Now()
	_, err := l.Lookup(context.Background(), strings.TrimPrefix(srv.URL, "http://")+"/step:1", nil)
	if err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("err %v after %s", err, time.Since(start))
	}
}

func TestRegistryHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://index.docker.io/v1/":            "index.docker.io",
		"docker.io":                              "index.docker.io",
		"registry-1.docker.io":                   "index.docker.io",
		"123.dkr.ecr.eu-central-1.amazonaws.com": "123.dkr.ecr.eu-central-1.amazonaws.com",
		"https://Registry.Example.com:5000/path": "registry.example.com:5000",
		" ghcr.io ":                              "ghcr.io",
	} {
		if got := registryHost(in); got != want {
			t.Errorf("registryHost(%q) = %q, want %q", in, got, want)
		}
	}
	hub, _ := name.ParseReference("ubuntu:24.04")
	if registryHost(hub.Context().RegistryStr()) != "index.docker.io" {
		t.Errorf("Docker Hub images: %s", hub.Context().RegistryStr())
	}
}
