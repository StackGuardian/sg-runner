package steps

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ImageConfig is what a step image runs by default.
type ImageConfig struct {
	Entrypoint []string
	Cmd        []string
}

// ImageConfigs looks up step images' configs.
type ImageConfigs interface {
	Lookup(ctx context.Context, image string, auth *RegistryAuth) (ImageConfig, error)
}

// Registry reads image configs from their registries: the manifest and the
// config blob, never the layers.
type Registry struct {
	// Platform picks an index's image: the broker's own, as it runs on the
	// step's node.
	Platform v1.Platform
	Timeout  time.Duration
	TTL      time.Duration
	// Transport is for tests (remote's default when nil).
	Transport http.RoundTripper
	// Now is the clock (time.Now when nil).
	Now func() time.Time

	mu    sync.Mutex
	cache map[string]cachedConfig
}

type cachedConfig struct {
	config ImageConfig
	at     time.Time
}

// NewRegistry returns a lookup for this platform, with a 20s timeout and a
// 10 minute cache.
func NewRegistry() *Registry {
	return &Registry{
		Platform: v1.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH},
		Timeout:  20 * time.Second,
		TTL:      10 * time.Minute,
	}
}

func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Lookup returns an image's entrypoint and cmd, from the cache when fresh.
// auth is used for the image's registry only, else access is anonymous.
func (r *Registry) Lookup(ctx context.Context, image string, auth *RegistryAuth) (ImageConfig, error) {
	r.mu.Lock()
	c, ok := r.cache[image]
	r.mu.Unlock()
	if ok && r.now().Sub(c.at) < r.TTL {
		return c.config, nil
	}

	ref, err := name.ParseReference(image)
	if err != nil {
		return ImageConfig{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	opts := []remote.Option{remote.WithContext(ctx), remote.WithAuth(authFor(ref.Context().Registry, auth))}
	if r.Transport != nil {
		opts = append(opts, remote.WithTransport(r.Transport))
	}
	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return ImageConfig{}, err
	}
	var img v1.Image
	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return ImageConfig{}, err
		}
		m, err := idx.IndexManifest()
		if err != nil {
			return ImageConfig{}, err
		}
		d, err := pickPlatform(m.Manifests, r.Platform)
		if err != nil {
			return ImageConfig{}, err
		}
		if img, err = idx.Image(d.Digest); err != nil {
			return ImageConfig{}, err
		}
	} else if img, err = desc.Image(); err != nil {
		return ImageConfig{}, err
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return ImageConfig{}, err
	}
	out := ImageConfig{Entrypoint: cf.Config.Entrypoint, Cmd: cf.Config.Cmd}

	r.mu.Lock()
	if r.cache == nil {
		r.cache = map[string]cachedConfig{}
	}
	for k, v := range r.cache {
		if r.now().Sub(v.at) >= r.TTL {
			delete(r.cache, k)
		}
	}
	r.cache[image] = cachedConfig{config: out, at: r.now()}
	r.mu.Unlock()
	return out, nil
}

// pickPlatform is an index's image for platform, else linux/amd64, else the
// first linux one (attestations and the like have no os).
func pickPlatform(ms []v1.Descriptor, want v1.Platform) (v1.Descriptor, error) {
	match := func(os, arch string) (v1.Descriptor, bool) {
		for _, d := range ms {
			if d.Platform != nil && d.Platform.OS == os && (arch == "" || d.Platform.Architecture == arch) {
				return d, true
			}
		}
		return v1.Descriptor{}, false
	}
	for _, p := range []v1.Platform{want, {OS: "linux", Architecture: "amd64"}, {OS: "linux"}} {
		if d, ok := match(p.OS, p.Architecture); ok {
			return d, nil
		}
	}
	return v1.Descriptor{}, errors.New("no linux image in the index")
}

// authFor is auth when it's for reg, anonymous otherwise.
func authFor(reg name.Registry, auth *RegistryAuth) authn.Authenticator {
	if auth == nil || registryHost(auth.Registry) != registryHost(reg.RegistryStr()) {
		return authn.Anonymous
	}
	return authn.FromConfig(authn.AuthConfig{Username: auth.Username, Password: auth.Password})
}

// registryHost normalizes a registry as Docker credentials name it (a host,
// or https://index.docker.io/v1/ for Docker Hub).
func registryHost(r string) string {
	r = strings.ToLower(strings.TrimSpace(r))
	r = strings.TrimPrefix(strings.TrimPrefix(r, "https://"), "http://")
	if i := strings.Index(r, "/"); i >= 0 {
		r = r[:i]
	}
	switch r {
	case "docker.io", "registry-1.docker.io", "index.docker.io":
		return name.DefaultRegistry
	}
	return r
}

// wrapCommand is the step container's command under the wrapper: the image's
// entrypoint, then the request's args (Docker's command=) or the image's
// cmd. Empty when there's nothing to run.
func wrapCommand(cfg ImageConfig, args []string) []string {
	argv := append([]string{}, cfg.Entrypoint...)
	if len(args) > 0 {
		argv = append(argv, args...)
	} else {
		argv = append(argv, cfg.Cmd...)
	}
	if len(argv) == 0 {
		return nil
	}
	return append([]string{WrapperPath, "--"}, argv...)
}

// lookupError shortens a lookup error for an annotation.
func lookupError(err error) string {
	msg := fmt.Sprintf("image config lookup: %v", err)
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return msg
}
