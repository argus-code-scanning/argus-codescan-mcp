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
//  1. ARGUS_MCP_PYTHON / CODETESTING_MCP_PYTHON env var
//  2. argus-mcp on PATH          (pip install — dedicated MCP entrypoint)
//  3. argus / argus-scan + mcp   (pip install — CLI with mcp subcommand)
//  4. uvx --from argus-scan argus-mcp
//  5. python3/python -m argus.server
func Resolve() (*ServerCmd, error) {
	// 1. Explicit env override
	for _, key := range []string{"ARGUS_MCP_PYTHON", "CODETESTING_MCP_PYTHON"} {
		if envCmd := os.Getenv(key); envCmd != "" {
			return &ServerCmd{Path: envCmd}, nil
		}
	}

	// 2. Dedicated MCP entrypoint
	if path, err := exec.LookPath("argus-mcp"); err == nil {
		return &ServerCmd{Path: path}, nil
	}

	// 3. CLI with mcp subcommand
	for _, name := range []string{"argus", "argus-scan"} {
		if path, err := exec.LookPath(name); err == nil {
			return &ServerCmd{Path: path, Args: []string{"mcp"}}, nil
		}
	}

	// 4. uvx
	if path, err := exec.LookPath("uvx"); err == nil {
		return &ServerCmd{Path: path, Args: []string{"--from", "argus-scan", "argus-mcp"}}, nil
	}

	// 5. python -m
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
			"Or set ARGUS_MCP_PYTHON to the server executable path.",
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

// Version returns the version string from the installed Python package.
func Version() (string, error) {
	if _, err := Resolve(); err != nil {
		return "", err
	}

	// Prefer the CLI --version path (works for argus / argus-scan).
	for _, name := range []string{"argus", "argus-scan"} {
		if path, err := exec.LookPath(name); err == nil {
			out, err := exec.Command(path, "--version").Output()
			if err == nil {
				return string(out), nil
			}
		}
	}

	for _, py := range []string{"python3", "python"} {
		if path, err := exec.LookPath(py); err == nil {
			out, err := exec.Command(path, "-c", "import argus; print(argus.__version__)").Output()
			if err == nil {
				return string(out), nil
			}
		}
	}

	return "unknown", nil
}

// platformNote returns a platform-specific install hint.
func platformNote() string {
	switch runtime.GOOS {
	case "darwin":
		return "Tip: brew install semgrep trivy gitleaks"
	case "linux":
		return "Tip: see https://github.com/OkiriGabriel/argus-codescan-mcp/blob/main/docs/tool-setup.md"
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
