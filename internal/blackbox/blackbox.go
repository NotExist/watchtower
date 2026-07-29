// Package blackbox preserves forensic records of Watchtower's destructive
// actions: full configuration snapshots of containers about to be removed,
// and a persistent copy of the runtime log.
//
// Both exist because an interrupted update session — or a Watchtower
// self-update, which removes the old Watchtower container together with its
// `docker logs` history — can otherwise destroy the only records needed to
// reconstruct what happened and restore affected containers.
//
// Layout under the blackbox directory (WATCHTOWER_BLACKBOX_DIR, default
// /var/lib/watchtower/blackbox; set to "none" to disable):
//
//	containers/<name>-<shortID>-<unixts>.json  full inspect data per removal
//	logs/watchtower-<startts>.log              runtime log tee (mirrors stdout)
//
// Mount the directory from the host to persist records beyond the Watchtower
// container's own lifetime.
package blackbox

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/nicholas-fedor/watchtower/pkg/types"
)

const (
	// dirEnv overrides the blackbox directory; "none" disables the feature.
	dirEnv = "WATCHTOWER_BLACKBOX_DIR"
	// defaultDir stores records inside the container by default. They survive
	// a stop (inspectable via the exited instance) but not container removal —
	// bind-mount the directory to persist across replacements.
	defaultDir = "/var/lib/watchtower/blackbox"
	// disabledValue disables the blackbox entirely.
	disabledValue = "none"

	// containersSubdir holds per-removal container snapshots.
	containersSubdir = "containers"
	// logsSubdir holds runtime log copies.
	logsSubdir = "logs"

	// keepLogFiles bounds how many runtime log files are retained.
	keepLogFiles = 20

	fileMode = 0o600
	dirMode  = 0o700
)

// Dir returns the active blackbox directory, or "" when disabled.
func Dir() string {
	dir := os.Getenv(dirEnv)
	switch dir {
	case disabledValue:
		return ""
	case "":
		return defaultDir
	default:
		return dir
	}
}

// RecordContainerSnapshot persists the container's full inspect data (Config,
// HostConfig, network settings, mounts) before the container is destroyed.
// The complete JSON is also logged at debug level as a filesystem-free
// fallback channel.
//
// Failures are logged but never block the update flow — the snapshot is a
// safety net, not a gate.
//
// Parameters:
//   - log: Logger for diagnostics.
//   - container: Container about to be stopped and removed.
func RecordContainerSnapshot(log *zerolog.Logger, container types.Container) {
	clogVal := log.With().Str("container", container.Name()).Logger()
	clog := &clogVal

	info := container.ContainerInfo()
	if info == nil {
		clog.Debug().Msg("No container info available for blackbox snapshot")

		return
	}

	data, err := json.Marshal(info)
	if err != nil {
		clog.Warn().Err(err).Msg("Failed to serialize container snapshot")

		return
	}

	clog.Debug().
		Str("snapshot", string(data)).
		Msg("Container configuration snapshot before removal")

	dir := Dir()
	if dir == "" {
		return
	}

	target := filepath.Join(dir, containersSubdir)
	if err := os.MkdirAll(target, dirMode); err != nil {
		clog.Warn().Err(err).Msg("Failed to create blackbox directory")

		return
	}

	path := filepath.Join(target, snapshotFileName(container))
	if err := os.WriteFile(path, data, fileMode); err != nil {
		clog.Warn().Err(err).Msg("Failed to write container snapshot")

		return
	}

	clog.Info().Str("file", path).Msg("Recorded container snapshot before removal")
}

// snapshotFileName builds a filesystem-safe snapshot name from the container
// name, short ID, and timestamp, e.g. "HomeAssistant-032dd5d3b706-1753781115.json".
func snapshotFileName(container types.Container) string {
	name := strings.TrimPrefix(container.Name(), "/")
	sanitized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			return r
		default:
			return '_'
		}
	}, name)

	return fmt.Sprintf(
		"%s-%s-%d.json",
		sanitized,
		container.ID().ShortID(),
		time.Now().Unix(),
	)
}

// OpenLogWriter opens a per-process blackbox log file and returns it as an
// io.Writer for composition into the runtime logger via
// zerolog.MultiLevelWriter. It prunes files beyond keepLogFiles and returns
// nil when the blackbox is disabled or the directory is unusable.
//
// Call once, after the health-check short-circuit: a health-check invocation
// exits without logging, so opening a file there would only churn the log ring
// with empty files. The returned file is held open by the logger for the
// process lifetime; the OS reclaims the descriptor on exit.
func OpenLogWriter(log *zerolog.Logger) io.Writer {
	dir := Dir()
	if dir == "" {
		return nil
	}

	target := filepath.Join(dir, logsSubdir)
	if err := os.MkdirAll(target, dirMode); err != nil {
		log.Warn().Err(err).Msg("Failed to create blackbox log directory")

		return nil
	}

	pruneOldLogs(target)

	path := filepath.Join(target, fmt.Sprintf("watchtower-%d.log", time.Now().Unix()))

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to open blackbox log file")

		return nil
	}

	log.Debug().Str("file", path).Msg("Mirroring runtime log into blackbox")

	return file
}

// pruneOldLogs removes the oldest log files beyond the retention bound. Names
// embed the start timestamp, so lexicographic order tracks age.
func pruneOldLogs(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	names := make([]string, 0, len(entries))

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "watchtower-") &&
			strings.HasSuffix(entry.Name(), ".log") {
			names = append(names, entry.Name())
		}
	}

	if len(names) < keepLogFiles {
		return
	}

	sort.Strings(names)

	for _, name := range names[:len(names)-keepLogFiles+1] {
		_ = os.Remove(filepath.Join(dir, name))
	}
}
