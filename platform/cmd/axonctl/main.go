// Package main implements the axonctl CLI tool for AxonFlow administration.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "1.0.0"

func main() {
	rootCmd := &cobra.Command{
		Use:     "axonctl",
		Short:   "AxonFlow CLI tool",
		Long:    `axonctl is a command-line tool for managing AxonFlow resources and access.`,
		Version: version,
	}

	// Add subcommands
	rootCmd.AddCommand(docsCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// docsCmd returns the docs subcommand for managing documentation access.
func docsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "docs",
		Short: "Manage protected documentation access",
		Long:  `Manage access to protected documentation via Cloudflare Access.`,
	}

	cmd.AddCommand(docsGrantCmd())
	cmd.AddCommand(docsRevokeCmd())
	cmd.AddCommand(docsListCmd())

	return cmd
}
