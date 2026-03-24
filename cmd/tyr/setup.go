package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup [agent]",
	Short: "Setup Tyr for an AI agent",
	Long: `Setup Tyr integration for various AI coding agents.

Supported agents:
  - opencode     OpenCode
  - claude-code  Claude Code
  - cursor       Cursor
  - windsurf     Windsurf
  - antigravity  Antigravity
  - gemini-cli   Gemini CLI
  - vscode       VS Code (Copilot)
  - generic      Generic MCP client

Examples:
  tyr setup opencode
  tyr setup claude-code
  tyr setup cursor`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agent := args[0]
		installer := getInstaller(agent)
		if err := installer.Install(); err != nil {
			log.Fatal("Setup failed", "agent", agent, "error", err)
		}
		log.Info("Setup complete", "agent", agent)
		fmt.Println("\nRestart your AI agent to start using Tyr!")
	},
}

type Installer interface {
	Install() error
	Name() string
}

func getInstaller(agent string) Installer {
	switch agent {
	case "opencode":
		return &OpenCodeInstaller{}
	case "claude-code":
		return &ClaudeCodeInstaller{}
	case "cursor":
		return &CursorInstaller{}
	case "windsurf":
		return &WindsurfInstaller{}
	case "antigravity":
		return &AntigravityInstaller{}
	case "gemini-cli":
		return &GeminiCLIInstaller{}
	case "vscode":
		return &VSCodeInstaller{}
	default:
		return &GenericInstaller{}
	}
}

func resolveBinaryPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "tyr"
	}
	return exe
}

type OpenCodeInstaller struct{}

func (i *OpenCodeInstaller) Name() string { return "OpenCode" }
func (i *OpenCodeInstaller) Install() error {
	exe := resolveBinaryPath()

	if err := injectOpenCodeMCP("tyr", exe); err != nil {
		fmt.Printf("Warning: could not auto-register MCP in opencode.json: %v\n", err)
		fmt.Printf("  Add manually to your opencode.json under \"mcp\":\n")
		fmt.Printf("  \"tyr\": { \"type\": \"local\", \"command\": [%q, \"mcp\"], \"enabled\": true }\n", exe)
	}
	return nil
}

type ClaudeCodeInstaller struct{}

func (i *ClaudeCodeInstaller) Name() string { return "Claude Code" }
func (i *ClaudeCodeInstaller) Install() error {
	exe := resolveBinaryPath()
	dir := filepath.Join(os.Getenv("USERPROFILE"), ".claude", "mcp")
	if home, err := os.UserHomeDir(); err == nil {
		dir = filepath.Join(home, ".claude", "mcp")
	}
	os.MkdirAll(dir, 0755)

	entry := map[string]interface{}{
		"command": exe,
		"args":    []string{"mcp"},
	}
	data, _ := json.MarshalIndent(entry, "", "  ")
	dest := filepath.Join(dir, "tyr.json")
	return os.WriteFile(dest, data, 0644)
}

type CursorInstaller struct{}

func (i *CursorInstaller) Name() string { return "Cursor" }
func (i *CursorInstaller) Install() error {
	exe := resolveBinaryPath()
	appData := os.Getenv("APPDATA")
	if appData == "" {
		home, _ := os.UserHomeDir()
		appData = filepath.Join(home, "Library", "Application Support")
	}
	dir := filepath.Join(appData, "Cursor", "User", "globalStorage", "cursor-retrieval")
	os.MkdirAll(dir, 0755)
	configPath := filepath.Join(dir, "mcpServers.json")
	var config map[string]interface{}
	data, err := os.ReadFile(configPath)
	if err == nil {
		json.Unmarshal(data, &config)
	} else {
		config = map[string]interface{}{"mcpServers": make(map[string]interface{})}
	}
	mcpServers, _ := config["mcpServers"].(map[string]interface{})
	if mcpServers == nil {
		mcpServers = make(map[string]interface{})
		config["mcpServers"] = mcpServers
	}
	mcpServers["tyr"] = map[string]interface{}{"type": "command", "command": exe, "args": []string{"mcp"}, "env": make(map[string]string)}
	finalJSON, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile(configPath, finalJSON, 0644)
}

type WindsurfInstaller struct{}

func (i *WindsurfInstaller) Name() string { return "Windsurf" }
func (i *WindsurfInstaller) Install() error {
	exe := resolveBinaryPath()
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")
	os.MkdirAll(filepath.Dir(configPath), 0755)
	var config map[string]interface{}
	data, err := os.ReadFile(configPath)
	if err == nil {
		json.Unmarshal(data, &config)
	} else {
		config = map[string]interface{}{"mcpServers": make(map[string]interface{})}
	}
	mcpServers, _ := config["mcpServers"].(map[string]interface{})
	if mcpServers == nil {
		mcpServers = make(map[string]interface{})
		config["mcpServers"] = mcpServers
	}
	mcpServers["tyr"] = map[string]interface{}{"command": exe, "args": []string{"mcp"}}
	finalJSON, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile(configPath, finalJSON, 0644)
}

type AntigravityInstaller struct{}

func (i *AntigravityInstaller) Name() string { return "Antigravity" }
func (i *AntigravityInstaller) Install() error {
	exe := resolveBinaryPath()
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".gemini", "antigravity", "mcp_servers.json")
	os.MkdirAll(filepath.Dir(configPath), 0755)
	var mcpServers map[string]interface{}
	data, err := os.ReadFile(configPath)
	if err == nil {
		json.Unmarshal(data, &mcpServers)
	} else {
		mcpServers = make(map[string]interface{})
	}
	mcpServers["tyr"] = map[string]interface{}{"command": exe, "args": []string{"mcp"}}
	finalJSON, _ := json.MarshalIndent(mcpServers, "", "  ")
	return os.WriteFile(configPath, finalJSON, 0644)
}

type GeminiCLIInstaller struct{}

func (i *GeminiCLIInstaller) Name() string { return "Gemini CLI" }
func (i *GeminiCLIInstaller) Install() error {
	exe := resolveBinaryPath()
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".gemini", "settings.json")
	os.MkdirAll(filepath.Dir(configPath), 0755)
	var config map[string]json.RawMessage
	data, err := os.ReadFile(configPath)
	if err == nil {
		json.Unmarshal(data, &config)
	} else {
		config = make(map[string]json.RawMessage)
	}
	var mcpServers map[string]interface{}
	if raw, exists := config["mcpServers"]; exists {
		json.Unmarshal(raw, &mcpServers)
	} else {
		mcpServers = make(map[string]interface{})
	}
	mcpServers["tyr"] = map[string]interface{}{"command": exe, "args": []string{"mcp"}}
	mcpJSON, _ := json.Marshal(mcpServers)
	config["mcpServers"] = json.RawMessage(mcpJSON)
	finalJSON, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile(configPath, finalJSON, 0644)
}

type VSCodeInstaller struct{}

func (i *VSCodeInstaller) Name() string   { return "VS Code" }
func (i *VSCodeInstaller) Install() error { return (&GenericInstaller{}).Install() }

type GenericInstaller struct{}

func (i *GenericInstaller) Name() string { return "Generic MCP" }
func (i *GenericInstaller) Install() error {
	fmt.Printf("Generic MCP setup:\nCommand: %s\nArgs: mcp\n", resolveBinaryPath())
	return nil
}

func injectOpenCodeMCP(name, exe string) error {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = os.Getenv("USERPROFILE")
	}
	configPath := filepath.Join(home, ".config", "opencode", "opencode.json")

	var config map[string]interface{}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	mcp, exists := config["mcp"].(map[string]interface{})
	if !exists {
		mcp = make(map[string]interface{})
		config["mcp"] = mcp
	}

	if _, exists := mcp[name]; !exists {
		mcp[name] = map[string]interface{}{
			"type":    "local",
			"command": []string{exe, "mcp"},
			"enabled": true,
		}

		finalJSON, _ := json.MarshalIndent(config, "", "  ")
		return os.WriteFile(configPath, finalJSON, 0644)
	}

	return nil
}
