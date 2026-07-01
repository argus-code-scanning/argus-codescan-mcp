// Package bridge locates and spawns the argus-scan Python server,
// then proxies stdio between the caller and the server process.
package bridge

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
)

// ServerCmd represents a resolved command to start the MCP server.
type ServerCmd struct {
	Path string
	Args []string
}

// Resolve finds the best available command to start the Python MCP server.
// Resolution order:
//  1. CODETESTING_MCP_PYTHON env var
//  2. argus-scan on PATH  (pip install)
//  3. uvx argus-scan      (uv tool runner)
//  4. python3 -m argus.server
//  5. python -m argus.server
func Resolve() (*ServerCmd, error) {
	// 1. Explicit env override
	if envCmd := os.Getenv("CODETESTING_MCP_PYTHON"); envCmd != "" {
		return &ServerCmd{Path: envCmd}, nil
	}

	// 2. argus-scan CLI on PATH
	if path, err := exec.LookPath("argus-scan"); err == nil {
		return &ServerCmd{Path: path}, nil
	}

	// 3. uvx
	if path, err := exec.LookPath("uvx"); err == nil {
		return &ServerCmd{Path: path, Args: []string{"argus-scan"}}, nil
	}

	// 4. python3 -m
	for _, py := range []string{"python3", "python"} {
		if path, err := exec.LookPath(py); err == nil {
			return &ServerCmd{
				Path: path,
				Args: []string{"-m", "argus.server"},
			}, nil
		}
	}

	return nil, errors.New(
		"argus-scan Python server not found.\n" +
			"Install with: pip install argus-scan\n" +
			"Or set CODETESTING_MCP_PYTHON to the server executable path.",
	)
}

// IsAvailable returns true if a server can be resolved without error.
func IsAvailable() bool {
	_, err := Resolve()
	return err == nil
}

// Spawn starts the MCP server and wires its stdin/stdout to the provided
// reader/writer. It blocks until the process exits.
func Spawn(stdin io.Reader, stdout io.Writer, stderr io.Writer, extraEnv []string) error {
	cmd, err := Resolve()
	if err != nil {
		return err
	}

	args := append([]string{}, cmd.Args...)
	proc := exec.Command(cmd.Path, args...)
	proc.Stdin = stdin
	proc.Stdout = stdout
	proc.Stderr = stderr
	proc.Env = append(os.Environ(), extraEnv...)

	return proc.Run()
}

// Version returns the version string from the installed Python server.
func Version() (string, error) {
	cmd, err := Resolve()
	if err != nil {
		return "", err
	}

	// Build a command that prints the version and exits
	var proc *exec.Cmd
	if len(cmd.Args) > 0 {
		args := append(cmd.Args, "--version")
		proc = exec.Command(cmd.Path, args...)
	} else {
		proc = exec.Command(cmd.Path, "--version")
	}

	out, err := proc.Output()
	if err != nil {
		return "unknown", nil // --version may not be implemented yet
	}
	return string(out), nil
}

// platformNote returns a platform-specific install hint.
func platformNote() string {
	switch runtime.GOOS {
	case "darwin":
		return "Tip: brew install semgrep trivy gitleaks"
	case "linux":
		return "Tip: see https://github.com/GabrielOkiri/argus-mcp/blob/main/docs/tool-setup.md"
	default:
		return ""
	}
}

// CheckMessage returns a human-readable availability message.
func CheckMessage() string {
	cmd, err := Resolve()
	if err != nil {
		return fmt.Sprintf("❌  Python server not found: %v", err)
	}

	full := cmd.Path
	if len(cmd.Args) > 0 {
		full = full + " " + fmt.Sprint(cmd.Args)
	}
	note := platformNote()
	if note != "" {
		return fmt.Sprintf("✅  Python server found: %s\n   %s", full, note)
	}
	return fmt.Sprintf("✅  Python server found: %s", full)
}
