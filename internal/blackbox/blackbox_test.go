package blackbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/nicholas-fedor/watchtower/internal/actions/mocks"
)

// testLog returns a discarding logger for tests that only assert file output.
func testLog() *zerolog.Logger {
	l := zerolog.New(zerolog.Nop()).With().Timestamp().Logger()

	return &l
}

func TestDir(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{"", defaultDir},
		{"none", ""},
		{"/data/blackbox", "/data/blackbox"},
	}

	for _, tt := range tests {
		t.Run("value="+tt.value, func(t *testing.T) {
			t.Setenv(dirEnv, tt.value)

			if got := Dir(); got != tt.want {
				t.Errorf("Dir() with %q = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestRecordContainerSnapshot(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(dirEnv, dir)

	container := mocks.CreateMockContainer(
		"cont1234567890",
		"/Test-App",
		"example/app:latest",
		time.Now(),
	)

	RecordContainerSnapshot(testLog(), container)

	entries, err := os.ReadDir(filepath.Join(dir, containersSubdir))
	if err != nil {
		t.Fatalf("snapshot directory missing: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(entries))
	}

	name := entries[0].Name()
	if !strings.HasPrefix(name, "Test-App-") || !strings.HasSuffix(name, ".json") {
		t.Errorf("unexpected snapshot file name %q", name)
	}

	data, err := os.ReadFile(filepath.Join(dir, containersSubdir, name))
	if err != nil {
		t.Fatal(err)
	}

	var snapshot struct {
		Name   string `json:"Name"`
		Config struct {
			Image string `json:"Image"`
		} `json:"Config"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}

	if snapshot.Name != "/Test-App" || snapshot.Config.Image != "example/app:latest" {
		t.Errorf("snapshot content mismatch: %+v", snapshot)
	}
}

func TestRecordContainerSnapshotDisabled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(dirEnv, disabledValue)

	container := mocks.CreateMockContainer("id1", "/app", "example/app:latest", time.Now())
	RecordContainerSnapshot(testLog(), container)

	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("expected no files when disabled, got %d", len(entries))
	}
}

func TestOpenLogWriter(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(dirEnv, dir)

	writer := OpenLogWriter(testLog())
	if writer == nil {
		t.Fatal("OpenLogWriter returned nil for an enabled blackbox")
	}

	// Compose the writer the way SetupLogging does and emit an entry.
	teed := zerolog.New(zerolog.MultiLevelWriter(zerolog.Nop(), writer)).
		With().Timestamp().Logger()
	teed.Info().Msg("blackbox tee smoke test entry")

	entries, err := os.ReadDir(filepath.Join(dir, logsSubdir))
	if err != nil {
		t.Fatalf("log directory missing: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 log file, got %d", len(entries))
	}

	data, err := os.ReadFile(filepath.Join(dir, logsSubdir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(data), "blackbox tee smoke test entry") {
		t.Errorf("log file does not contain the emitted entry: %q", string(data))
	}
}

func TestOpenLogWriterDisabled(t *testing.T) {
	t.Setenv(dirEnv, disabledValue)

	if w := OpenLogWriter(testLog()); w != nil {
		t.Errorf("expected nil writer when blackbox disabled, got %T", w)
	}
}

func TestPruneOldLogs(t *testing.T) {
	dir := t.TempDir()

	for i := range 25 {
		name := filepath.Join(dir, "watchtower-"+strings.Repeat("0", 2)+string(rune('a'+i))+".log")
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	pruneOldLogs(dir)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Prune keeps keepLogFiles-1 existing files so the upcoming new file
	// lands within the bound.
	if len(entries) != keepLogFiles-1 {
		t.Errorf("expected %d files after prune, got %d", keepLogFiles-1, len(entries))
	}
}
