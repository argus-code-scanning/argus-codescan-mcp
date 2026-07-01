package bridge_test

import (
	"os"
	"testing"

	"github.com/GabrielOkiri/argus-mcp/internal/bridge"
)

func TestResolveEnvOverride(t *testing.T) {
	t.Setenv("CODETESTING_MCP_PYTHON", "/custom/path/server")

	cmd, err := bridge.Resolve()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cmd.Path != "/custom/path/server" {
		t.Errorf("expected /custom/path/server, got %q", cmd.Path)
	}
}

func TestResolveNoServerReturnsError(t *testing.T) {
	// Temporarily remove all resolution candidates from PATH
	original := os.Getenv("PATH")
	t.Setenv("PATH", "")
	t.Setenv("CODETESTING_MCP_PYTHON", "")
	defer os.Setenv("PATH", original)

	_, err := bridge.Resolve()
	if err == nil {
		t.Error("expected error when nothing is resolvable")
	}
}

func TestIsAvailableReturnsBool(t *testing.T) {
	// Just check it doesn't panic
	_ = bridge.IsAvailable()
}

func TestCheckMessageContainsStatus(t *testing.T) {
	msg := bridge.CheckMessage()
	if len(msg) == 0 {
		t.Error("CheckMessage returned empty string")
	}
}
