// Package recompress implements the zstd fallback pull path for Watchtower.
//
// Older Docker daemons (pre-23.0) cannot decompress OCI images published with
// zstd-compressed layers (application/vnd.oci.image.layer.v1.tar+zstd): the
// daemon downloads every layer and then fails during extraction with a generic
// "archive/tar: invalid tar header" error. This package works around that by
// pulling the image directly from the registry (bypassing the daemon),
// recompressing the layers to gzip, and injecting the result into the daemon
// via the image load API — the same mechanism as
// `skopeo copy --dest-compress-format gzip docker://… dir:… && skopeo copy dir:… docker-daemon:…`,
// implemented in-process with the containers/image library skopeo itself uses.
//
// The injected image carries the upstream tag manifest digest in the
// LabelUpstreamDigest image label. Because loaded images have no RepoDigests,
// the digest package uses this label to compare against the registry HEAD
// digest, keeping staleness checks cheap (a few KB per cycle) instead of
// re-downloading the full image every poll.
package recompress

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/rs/zerolog"

	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/directory"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/daemon"
	ociimage "github.com/containers/image/v5/image"
	"github.com/containers/image/v5/pkg/compression"
	"github.com/containers/image/v5/signature"
	imgtypes "github.com/containers/image/v5/types"
)

const (
	// LabelUpstreamDigest stores the upstream tag manifest digest (the digest
	// returned by a registry HEAD request for the tag — the index digest for
	// multi-arch images) on a recompressed image. It substitutes for the
	// RepoDigests entry a natively pulled image would have.
	LabelUpstreamDigest = "kai.upstream-digest"
	// LabelRecompressed marks an image as produced by this fallback path.
	LabelRecompressed = "kai.recompressed"
	// labelRecompressedValue records the transformation applied.
	labelRecompressedValue = "zstd-to-gzip"

	// envEnabled disables the fallback when set to "false"/"0"/"no".
	envEnabled = "WATCHTOWER_ZSTD_FALLBACK"
	// envWorkDir overrides the scratch directory (default os.TempDir()) used
	// for the recompressed layers (roughly the compressed image size).
	envWorkDir = "WATCHTOWER_ZSTD_WORKDIR"
)

// errNoConfigInManifest indicates a downloaded manifest without a config descriptor.
var errNoConfigInManifest = errors.New("manifest has no config descriptor")

// zstdErrorSignatures are substrings of daemon pull-stream errors that suggest
// the daemon failed to decompress zstd layers. The signature match alone is NOT
// treated as proof (dockerd 20.10 reports the generic "invalid tar header");
// FallbackPull independently confirms via the registry manifest media types
// before recompressing.
var zstdErrorSignatures = []string{
	"archive/tar: invalid tar header", // dockerd 20.10.x: ApplyLayer on zstd data (verified)
	"tar+zstd",                        // daemons that reject the media type explicitly
	"unsupported compression",
}

// Enabled reports whether the zstd fallback is active (default true; disable
// with WATCHTOWER_ZSTD_FALLBACK=false).
func Enabled() bool {
	switch strings.ToLower(os.Getenv(envEnabled)) {
	case "false", "0", "no":
		return false
	default:
		return true
	}
}

// IsZstdPullError reports whether a pull error matches a known zstd failure
// signature. Callers must still confirm via FallbackPull's manifest probe —
// the signatures overlap with genuinely corrupt archives.
//
// Parameters:
//   - err: Error surfaced from the daemon pull stream.
//
// Returns:
//   - bool: True if the error looks like a zstd decompression failure.
func IsZstdPullError(err error) bool {
	if err == nil {
		return false
	}

	msg := err.Error()
	for _, sig := range zstdErrorSignatures {
		if strings.Contains(msg, sig) {
			return true
		}
	}

	return false
}

// FallbackPull confirms the upstream image uses zstd layers and, if so, pulls
// it directly from the registry, recompresses the layers to gzip, stamps the
// upstream digest label, and injects the result into the Docker daemon under
// the image's own tag.
//
// Parameters:
//   - log: Logger for progress and diagnostics.
//   - ctx: Context for operation control.
//   - imageName: Image reference (tag form) that failed the native pull.
//   - registryAuth: Base64-encoded auth config (may be empty).
//   - osChoice: Target OS (empty = runtime default).
//   - archChoice: Target architecture (empty = runtime default).
//
// Returns:
//   - bool: True if the upstream image was confirmed zstd and handled here;
//     false if the manifest shows no zstd layers (error was something else).
//   - error: Non-nil if probing or the recompressed pull fails.
func FallbackPull(log *zerolog.Logger,
	ctx context.Context,
	imageName string,
	registryAuth string,
	osChoice string,
	archChoice string,
) (bool, error) {
	clogVal := log.With().Str("image", imageName).Logger()
	clog := &clogVal

	named, err := reference.ParseNormalizedNamed(imageName)
	if err != nil {
		return false, fmt.Errorf("failed to parse image reference %q: %w", imageName, err)
	}

	tagged := reference.TagNameOnly(named)

	srcRef, err := docker.ParseReference("//" + tagged.String())
	if err != nil {
		return false, fmt.Errorf("failed to build registry reference: %w", err)
	}

	authConfig, err := dockerAuthFromBase64(registryAuth)
	if err != nil {
		return false, fmt.Errorf("failed to decode registry auth: %w", err)
	}

	sys := &imgtypes.SystemContext{
		OSChoice:           osChoice,
		ArchitectureChoice: archChoice,
		DockerAuthConfig:   authConfig,
	}

	// Second factor: confirm via the registry manifest that the layers really
	// are zstd before paying for a full re-download.
	upstreamDigest, hasZstd, err := probeManifest(ctx, sys, srcRef)
	if err != nil {
		return false, fmt.Errorf("failed to probe upstream manifest: %w", err)
	}

	if !hasZstd {
		clog.Debug().Msg("Upstream manifest has no zstd layers, not a zstd failure")

		return false, nil
	}

	clog.Info().
		Str("upstream_digest", upstreamDigest).
		Msg("Upstream image uses zstd layers, pulling via gzip recompression")

	if err := pullRecompressed(ctx, sys, srcRef, tagged, upstreamDigest); err != nil {
		return true, err
	}

	clog.Info().Msg("Recompressed image injected into daemon")

	return true, nil
}

// probeManifest fetches the tag's top-level manifest, returning its digest
// (the value a registry HEAD request reports for the tag) and whether the
// platform image's layers use zstd compression.
func probeManifest(
	ctx context.Context,
	sys *imgtypes.SystemContext,
	srcRef imgtypes.ImageReference,
) (string, bool, error) {
	src, err := srcRef.NewImageSource(ctx, sys)
	if err != nil {
		return "", false, fmt.Errorf("failed to open image source: %w", err)
	}
	defer func() { _ = src.Close() }()

	topManifest, _, err := src.GetManifest(ctx, nil)
	if err != nil {
		return "", false, fmt.Errorf("failed to fetch manifest: %w", err)
	}

	upstreamDigest := digest.FromBytes(topManifest).String()

	// Resolves a manifest list to the platform instance selected by sys.
	img, err := ociimage.FromUnparsedImage(ctx, sys, ociimage.UnparsedInstance(src, nil))
	if err != nil {
		return "", false, fmt.Errorf("failed to resolve platform image: %w", err)
	}

	for _, layer := range img.LayerInfos() {
		if strings.Contains(layer.MediaType, "zstd") {
			return upstreamDigest, true, nil
		}
	}

	return upstreamDigest, false, nil
}

// pullRecompressed copies the image from the registry into a scratch dir with
// layers recompressed to gzip, injects the state labels into the image config,
// and loads the result into the daemon under the image's own tag.
func pullRecompressed(
	ctx context.Context,
	sys *imgtypes.SystemContext,
	srcRef imgtypes.ImageReference,
	tagged reference.Named,
	upstreamDigest string,
) error {
	policyCtx, err := signature.NewPolicyContext(&signature.Policy{
		Default: []signature.PolicyRequirement{signature.NewPRInsecureAcceptAnything()},
	})
	if err != nil {
		return fmt.Errorf("failed to create signature policy: %w", err)
	}
	defer func() { _ = policyCtx.Destroy() }()

	workBase := os.Getenv(envWorkDir)
	if workBase == "" {
		workBase = os.TempDir()
	}

	// The scratch-based watchtower image may lack /tmp entirely.
	if err := os.MkdirAll(workBase, 0o700); err != nil {
		return fmt.Errorf("failed to create work directory %q: %w", workBase, err)
	}

	work, err := os.MkdirTemp(workBase, "watchtower-zstd-")
	if err != nil {
		return fmt.Errorf("failed to create scratch directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(work) }()

	dirRef, err := directory.NewReference(filepath.Join(work, "img"))
	if err != nil {
		return fmt.Errorf("failed to build scratch reference: %w", err)
	}

	// Stage 1: registry → dir with gzip recompression (equivalent to
	// `skopeo copy --dest-compress --dest-compress-format gzip`). A one-step
	// registry → daemon copy is impossible: zstd layers cannot be represented
	// in the Docker schema2 manifest the daemon transport requires.
	destSys := *sys
	destSys.DirForceCompress = true
	destSys.CompressionFormat = &compression.Gzip

	if _, err := copy.Image(ctx, policyCtx, dirRef, srcRef, &copy.Options{
		SourceCtx:          sys,
		DestinationCtx:     &destSys,
		ImageListSelection: copy.CopySystemImage,
	}); err != nil {
		return fmt.Errorf("failed to copy image from registry: %w", err)
	}

	labels := map[string]string{
		LabelUpstreamDigest: upstreamDigest,
		LabelRecompressed:   labelRecompressedValue,
	}
	if err := injectLabels(filepath.Join(work, "img"), labels); err != nil {
		return fmt.Errorf("failed to inject state labels: %w", err)
	}

	daemonRef, err := daemon.ParseReference(tagged.String())
	if err != nil {
		return fmt.Errorf("failed to build daemon reference: %w", err)
	}

	// Stage 2: dir → daemon (layers now gzip, loadable by any daemon).
	if _, err := copy.Image(ctx, policyCtx, daemonRef, dirRef, &copy.Options{
		DestinationCtx: sys,
	}); err != nil {
		return fmt.Errorf("failed to load image into daemon: %w", err)
	}

	return nil
}

// injectLabels rewrites the image config blob in a dir-transport layout to add
// the given labels, updating the manifest's config descriptor to match.
func injectLabels(dirPath string, labels map[string]string) error {
	manifestPath := filepath.Join(dirPath, "manifest.json")

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest map[string]any
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return fmt.Errorf("failed to parse manifest: %w", err)
	}

	configDesc, ok := manifest["config"].(map[string]any)
	if !ok {
		return errNoConfigInManifest
	}

	configDigest, _ := configDesc["digest"].(string)
	configPath := filepath.Join(dirPath, strings.TrimPrefix(configDigest, "sha256:"))

	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read image config: %w", err)
	}

	var imageConfig map[string]any
	if err := json.Unmarshal(configBytes, &imageConfig); err != nil {
		return fmt.Errorf("failed to parse image config: %w", err)
	}

	runtimeConfig, _ := imageConfig["config"].(map[string]any)
	if runtimeConfig == nil {
		runtimeConfig = map[string]any{}
		imageConfig["config"] = runtimeConfig
	}

	labelMap, _ := runtimeConfig["Labels"].(map[string]any)
	if labelMap == nil {
		labelMap = map[string]any{}
		runtimeConfig["Labels"] = labelMap
	}

	for key, value := range labels {
		labelMap[key] = value
	}

	newConfigBytes, err := json.Marshal(imageConfig)
	if err != nil {
		return fmt.Errorf("failed to serialize image config: %w", err)
	}

	newDigest := digest.FromBytes(newConfigBytes)
	if err := os.WriteFile(filepath.Join(dirPath, newDigest.Encoded()), newConfigBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write image config: %w", err)
	}

	configDesc["digest"] = newDigest.String()
	configDesc["size"] = len(newConfigBytes)

	newManifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("failed to serialize manifest: %w", err)
	}

	if err := os.WriteFile(manifestPath, newManifestBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	if old := strings.TrimPrefix(configDigest, "sha256:"); old != newDigest.Encoded() {
		_ = os.Remove(filepath.Join(dirPath, old))
	}

	return nil
}

// dockerAuthFromBase64 converts a Docker API X-Registry-Auth payload into
// containers/image auth credentials. Empty input yields nil (anonymous).
func dockerAuthFromBase64(registryAuth string) (*imgtypes.DockerAuthConfig, error) {
	if registryAuth == "" {
		return nil, nil
	}

	raw, err := base64.URLEncoding.DecodeString(registryAuth)
	if err != nil {
		raw, err = base64.StdEncoding.DecodeString(registryAuth)
		if err != nil {
			return nil, fmt.Errorf("failed to decode auth payload: %w", err)
		}
	}

	var authConfig struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		IdentityToken string `json:"identitytoken"`
	}
	if err := json.Unmarshal(raw, &authConfig); err != nil {
		return nil, fmt.Errorf("failed to parse auth payload: %w", err)
	}

	return &imgtypes.DockerAuthConfig{
		Username:      authConfig.Username,
		Password:      authConfig.Password,
		IdentityToken: authConfig.IdentityToken,
	}, nil
}
