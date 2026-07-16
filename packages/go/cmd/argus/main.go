// argus-scan Go CLI
//
// A thin binary that locates the Python MCP server and either:
//   - Starts it in stdio mode (default, for MCP clients)
//   - Runs a quick check/config subcommand (for humans)
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/OkiriGabriel/argus-codescan-mcp/internal/bridge"
)

var version = "0.1.0" // overridden by -ldflags at build time

func main() {
	root := &cobra.Command{
		Use:     "argus-scan",
		Short:   "MCP server for comprehensive code security testing",
		Long:    "Starts the argus-scan Python MCP server over stdio.",
		Version: version,
		// Default action: start the server
		RunE: func(cmd *cobra.Command, args []string) error {
			return bridge.Spawn(os.Stdin, os.Stdout, os.Stderr, nil)
		},
		SilenceUsage: true,
	}

	root.AddCommand(checkCmd(), configCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// checkCmd verifies the Python server is available.
func checkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Check if the Python MCP server is available",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(bridge.CheckMessage())
		},
	}
}

// configCmd prints a ready-to-paste MCP client configuration.
func configCmd() *cobra.Command {
	var method string

	c := &cobra.Command{
		Use:   "config",
		Short: "Print MCP client configuration JSON",
		Long:  "Prints a ready-to-paste JSON snippet for Cursor, Claude Desktop, or any MCP client.",
		Run: func(cmd *cobra.Command, args []string) {
			configs := map[string]string{
				"pip": `{
  "mcpServers": {
    "argus": {
      "command": "argus-mcp"
    }
  }
}`,
				"uvx": `{
  "mcpServers": {
    "argus": {
      "command": "uvx",
      "args": ["--from", "argus-scan", "argus-mcp"]
    }
  }
}`,
				"npx": `{
  "mcpServers": {
    "argus": {
      "command": "npx",
      "args": ["-y", "argus-codescan", "mcp"]
    }
  }
}`,
				"go": `{
  "mcpServers": {
    "argus": {
      "command": "argus-scan"
    }
  }
}`,
			}

			if cfg, ok := configs[method]; ok {
				fmt.Println(cfg)
			} else {
				fmt.Fprintf(os.Stderr, "unknown method %q — choose: pip, uvx, npx, go\n", method)
				os.Exit(1)
			}
		},
	}

	c.Flags().StringVarP(&method, "method", "m", "uvx", "Install method: pip, uvx, npx, go")
	return c
}
