package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	dockerClient "github.com/moby/moby/client"

	"github.com/nicholas-fedor/watchtower/internal/logging"
	"github.com/nicholas-fedor/watchtower/pkg/container"
)

// errPullsFailed indicates that at least one requested image failed to pull.
var errPullsFailed = errors.New("one or more image pulls failed")

// init registers the pull command with the root command.
func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "pull IMAGE [IMAGE...]",
		Short: "Pull images with the zstd fallback (for daemons that cannot pull zstd layers)",
		Long: `Pulls one or more images through the same zstd-safe path used for container
updates: a native daemon pull first, then gzip recompression via the registry
when the daemon cannot decompress zstd layers.

Use this to bring a brand-new zstd image onto an old daemon, where a plain
"docker pull" fails and the update fallback never triggers because no container
references the image yet. Typically invoked inside a running Watchtower
container:

  docker exec <watchtower> /watchtower pull nginx:latest`,
		RunE: runPullE,
		Args: cobra.MinimumNArgs(1),
	})
}

// runPullE pulls each requested image, continuing past individual failures.
//
// Parameters:
//   - _: The cobra command (unused).
//   - args: Image references to pull.
//
// Returns:
//   - error: Non-nil if any image failed to pull.
func runPullE(_ *cobra.Command, args []string) error {
	log := logging.New(os.Stderr, logging.InfoLevel)

	// FromEnv honors DOCKER_HOST and friends, with automatic API version
	// negotiation — required for old daemons, the fallback's whole audience.
	api, err := dockerClient.New(dockerClient.FromEnv)
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer api.Close()

	failed := 0

	for _, imageName := range args {
		clogVal := log.With().Str("image", imageName).Logger()
		clog := &clogVal
		clog.Info().Msg("Pulling image")

		if err := container.PullImageDirect(clog, context.Background(), api, imageName); err != nil {
			clog.Error().Err(err).Msg("Pull failed")

			failed++

			continue
		}

		clog.Info().Msg("Pull completed")
	}

	if failed > 0 {
		return fmt.Errorf("%w: %d of %d", errPullsFailed, failed, len(args))
	}

	return nil
}
