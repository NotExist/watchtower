package recompress

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"
)

func TestIsZstdPullError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "dockerd 20.10 zstd extraction failure (verified on real daemon)",
			err: errors.New(
				"failed to register layer: ApplyLayer exit status 1 stdout:  stderr: archive/tar: invalid tar header",
			),
			want: true,
		},
		{
			name: "explicit media type rejection",
			err:  errors.New(`unsupported media type application/vnd.oci.image.layer.v1.tar+zstd`),
			want: true,
		},
		{
			name: "network error",
			err:  errors.New("Get \"https://registry-1.docker.io/v2/\": net/http: TLS handshake timeout"),
			want: false,
		},
		{
			name: "not found",
			err:  errors.New("manifest for foo:latest not found"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsZstdPullError(tt.err); got != tt.want {
				t.Errorf("IsZstdPullError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnabled(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"", true},
		{"true", true},
		{"1", true},
		{"false", false},
		{"FALSE", false},
		{"0", false},
		{"no", false},
	}

	for _, tt := range tests {
		t.Run("value="+tt.value, func(t *testing.T) {
			t.Setenv(envEnabled, tt.value)

			if got := Enabled(); got != tt.want {
				t.Errorf("Enabled() with %q = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestDockerAuthFromBase64(t *testing.T) {
	t.Run("empty auth is anonymous", func(t *testing.T) {
		got, err := dockerAuthFromBase64("")
		if err != nil || got != nil {
			t.Errorf("dockerAuthFromBase64(\"\") = %v, %v, want nil, nil", got, err)
		}
	})

	t.Run("url-encoded credentials round-trip", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]string{
			"username": "user",
			"password": "pass",
		})

		got, err := dockerAuthFromBase64(base64.URLEncoding.EncodeToString(payload))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got.Username != "user" || got.Password != "pass" {
			t.Errorf("credentials = %+v, want user/pass", got)
		}
	})

	t.Run("std-encoded fallback", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]string{"username": "u"})

		got, err := dockerAuthFromBase64(base64.StdEncoding.EncodeToString(payload))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got.Username != "u" {
			t.Errorf("username = %q, want %q", got.Username, "u")
		}
	})

	t.Run("garbage input errors", func(t *testing.T) {
		if _, err := dockerAuthFromBase64("!!not-base64!!"); err == nil {
			t.Error("expected error for invalid base64")
		}
	})
}

// writeDirLayout builds a minimal dir-transport layout with a config blob and
// manifest referencing it, mirroring what `skopeo copy … dir:` produces.
func writeDirLayout(t *testing.T, imageConfig map[string]any) (string, string) {
	t.Helper()

	dirPath := t.TempDir()

	configBytes, err := json.Marshal(imageConfig)
	if err != nil {
		t.Fatal(err)
	}

	configDigest := digest.FromBytes(configBytes)
	if err := os.WriteFile(filepath.Join(dirPath, configDigest.Encoded()), configBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest":    configDigest.String(),
			"size":      len(configBytes),
		},
		"layers": []any{},
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dirPath, "manifest.json"), manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	return dirPath, configDigest.Encoded()
}

// readInjectedLayout re-reads the layout, verifying manifest/config coherence,
// and returns the labels of the (re-written) config.
func readInjectedLayout(t *testing.T, dirPath string) map[string]any {
	t.Helper()

	manifestBytes, err := os.ReadFile(filepath.Join(dirPath, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}

	var manifest struct {
		Config struct {
			Digest string `json:"digest"`
			Size   int    `json:"size"`
		} `json:"config"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}

	configBytes, err := os.ReadFile(
		filepath.Join(dirPath, digest.Digest(manifest.Config.Digest).Encoded()),
	)
	if err != nil {
		t.Fatalf("config blob named in manifest is missing: %v", err)
	}

	// The manifest descriptor must match the rewritten blob exactly, or the
	// dir → daemon copy would fail digest verification.
	if got := digest.FromBytes(configBytes).String(); got != manifest.Config.Digest {
		t.Errorf("config digest mismatch: manifest %s, blob %s", manifest.Config.Digest, got)
	}

	if manifest.Config.Size != len(configBytes) {
		t.Errorf("config size mismatch: manifest %d, blob %d", manifest.Config.Size, len(configBytes))
	}

	var imageConfig struct {
		Config struct {
			Labels map[string]any `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(configBytes, &imageConfig); err != nil {
		t.Fatal(err)
	}

	return imageConfig.Config.Labels
}

func TestInjectLabels(t *testing.T) {
	t.Run("adds labels preserving existing ones", func(t *testing.T) {
		dirPath, oldConfig := writeDirLayout(t, map[string]any{
			"architecture": "amd64",
			"os":           "linux",
			"config": map[string]any{
				"Env":    []any{"PATH=/usr/bin"},
				"Labels": map[string]any{"org.example.existing": "keep-me"},
			},
		})

		err := injectLabels(dirPath, map[string]string{
			LabelUpstreamDigest: "sha256:abc123",
			LabelRecompressed:   labelRecompressedValue,
		})
		if err != nil {
			t.Fatalf("injectLabels: %v", err)
		}

		labels := readInjectedLayout(t, dirPath)
		if labels[LabelUpstreamDigest] != "sha256:abc123" {
			t.Errorf("upstream digest label = %v", labels[LabelUpstreamDigest])
		}

		if labels[LabelRecompressed] != labelRecompressedValue {
			t.Errorf("recompressed label = %v", labels[LabelRecompressed])
		}

		if labels["org.example.existing"] != "keep-me" {
			t.Errorf("existing label lost: %v", labels)
		}

		// Stale config blob should be gone.
		if _, err := os.Stat(filepath.Join(dirPath, oldConfig)); !os.IsNotExist(err) {
			t.Errorf("old config blob still present: %v", err)
		}
	})

	t.Run("creates Labels when config has none", func(t *testing.T) {
		dirPath, _ := writeDirLayout(t, map[string]any{
			"architecture": "amd64",
			"os":           "linux",
			"config":       map[string]any{"Env": []any{"A=b"}},
		})

		if err := injectLabels(dirPath, map[string]string{LabelUpstreamDigest: "sha256:def"}); err != nil {
			t.Fatalf("injectLabels: %v", err)
		}

		labels := readInjectedLayout(t, dirPath)
		if labels[LabelUpstreamDigest] != "sha256:def" {
			t.Errorf("upstream digest label = %v", labels[LabelUpstreamDigest])
		}
	})

	t.Run("missing manifest errors", func(t *testing.T) {
		if err := injectLabels(t.TempDir(), map[string]string{"a": "b"}); err == nil {
			t.Error("expected error for missing manifest")
		}
	})
}
