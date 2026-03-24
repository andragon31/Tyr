package main

import (
	"os"

	"github.com/andragon31/tyr/internal/graph"
	"github.com/andragon31/tyr/internal/mcp"
	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
)

var logger *log.Logger

func main() {
	logger = log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "🐺 Tyr",
	})

	rootCmd := &cobra.Command{
		Use:   "tyr",
		Short: "Tyr - Security, Validation & Standards Layer",
		Run:   func(cmd *cobra.Command, args []string) {},
	}

	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(mcpCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(setupCmd)

	rootCmd.PersistentFlags().StringP("data-dir", "d", ".tyr", "Data directory")

	if err := rootCmd.Execute(); err != nil {
		logger.Fatal("Error executing command", "error", err)
	}
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Tyr",
	Run: func(cmd *cobra.Command, args []string) {
		dataDir, _ := cmd.Flags().GetString("data-dir")
		g, err := graph.New(dataDir)
		if err != nil {
			logger.Fatal("Failed to initialize graph", "error", err)
		}
		defer g.Close()

		if err := g.Init(); err != nil {
			logger.Fatal("Failed to init database", "error", err)
		}

		logger.Info("Tyr initialized", "data_dir", dataDir)
	},
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start Tyr HTTP server",
	Run: func(cmd *cobra.Command, args []string) {
		dataDir, _ := cmd.Flags().GetString("data-dir")
		port, _ := cmd.Flags().GetInt("port")

		g, err := graph.New(dataDir)
		if err != nil {
			logger.Fatal("Failed to create graph", "error", err)
		}
		defer g.Close()

		if err := g.Init(); err != nil {
			logger.Fatal("Failed to init database", "error", err)
		}

		server := mcp.NewServer(g, logger)
		logger.Info("Tyr server starting", "port", port)
		server.RunHTTP(port)
	},
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run Tyr MCP server",
	Run: func(cmd *cobra.Command, args []string) {
		dataDir, _ := cmd.Flags().GetString("data-dir")

		g, err := graph.New(dataDir)
		if err != nil {
			logger.Fatal("Failed to create graph", "error", err)
		}
		defer g.Close()

		if err := g.Init(); err != nil {
			logger.Fatal("Failed to init database", "error", err)
		}

		server := mcp.NewServer(g, logger)
		server.RunStdio()
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version",
	Run: func(cmd *cobra.Command, args []string) {
		logger.Info("Tyr v1.0.0 - Security, Validation & Standards Layer")
	},
}
