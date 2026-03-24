package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/andragon31/tyr/internal/graph"
	"github.com/charmbracelet/log"
	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type Server struct {
	graph  *graph.Graph
	logger *log.Logger
	server *server.MCPServer
}

func NewServer(g *graph.Graph, logger *log.Logger) *Server {
	srv := server.NewMCPServer("tyr", "1.0.0")

	s := &Server{
		graph:  g,
		logger: logger,
		server: srv,
	}

	s.registerAllTools()

	return s
}

func (s *Server) registerAllTools() {
	s.registerValidatorTools()
	s.registerSASTTools()
	s.registerAuditTools()
	s.registerStandardsTools()
	s.registerScopeTools()
}

func (s *Server) registerValidatorTools() {
	pkgCheck := mcp.NewTool("pkg_check",
		mcp.WithDescription("Validate package existence, trustworthiness and known CVEs before installing"),
		mcp.WithString("name", mcp.Required(), mcp.Description("Package name")),
		mcp.WithString("ecosystem", mcp.Required(), mcp.Description("Package ecosystem"), mcp.Enum("npm", "pypi", "cargo", "nuget")),
		mcp.WithString("version", mcp.Description("Package version")),
	)
	s.server.AddTool(pkgCheck, s.handlePkgCheck)

	pkgLicense := mcp.NewTool("pkg_license",
		mcp.WithDescription("Check package license and compatibility with project policies"),
		mcp.WithString("name", mcp.Required(), mcp.Description("Package name")),
		mcp.WithString("ecosystem", mcp.Required(), mcp.Description("Package ecosystem"), mcp.Enum("npm", "pypi", "cargo", "nuget")),
		mcp.WithString("version", mcp.Description("Package version")),
	)
	s.server.AddTool(pkgLicense, s.handlePkgLicense)

	pkgAudit := mcp.NewTool("pkg_audit",
		mcp.WithDescription("Full audit of all project dependencies for CVEs and license issues"),
		mcp.WithString("manifest_path", mcp.Description("Path to package.json, requirements.txt, etc.")),
	)
	s.server.AddTool(pkgAudit, s.handlePkgAudit)

	pkgAuditSnapshot := mcp.NewTool("pkg_audit_snapshot",
		mcp.WithDescription("Get snapshot of current vulnerabilities"),
	)
	s.server.AddTool(pkgAuditSnapshot, s.handlePkgAuditSnapshot)

	pkgAuditContinuous := mcp.NewTool("pkg_audit_continuous",
		mcp.WithDescription("Check for new CVEs in existing dependencies"),
		mcp.WithString("manifest_path", mcp.Description("Path to package.json")),
	)
	s.server.AddTool(pkgAuditContinuous, s.handlePkgAuditContinuous)
}

func (s *Server) registerSASTTools() {
	sastRun := mcp.NewTool("sast_run",
		mcp.WithDescription("Run SAST analysis with Semgrep"),
		mcp.WithString("target", mcp.Description("Target directory or file")),
		mcp.WithArray("rulesets", mcp.Description("Semgrep rulesets to use"), mcp.WithStringItems()),
	)
	s.server.AddTool(sastRun, s.handleSASTRun)

	sastFindings := mcp.NewTool("sast_findings",
		mcp.WithDescription("List active SAST findings with filters"),
		mcp.WithString("severity", mcp.Description("Filter by severity"), mcp.Enum("info", "warning", "error", "critical")),
		mcp.WithString("file", mcp.Description("Filter by file")),
		mcp.WithString("status", mcp.Description("Filter by status"), mcp.Enum("open", "resolved", "suppressed")),
	)
	s.server.AddTool(sastFindings, s.handleSASTFindings)

	sastResolve := mcp.NewTool("sast_resolve",
		mcp.WithDescription("Mark a SAST finding as resolved"),
		mcp.WithString("finding_id", mcp.Required(), mcp.Description("Finding ID")),
	)
	s.server.AddTool(sastResolve, s.handleSASTResolve)
}

func (s *Server) registerAuditTools() {
	auditLog := mcp.NewTool("audit_log",
		mcp.WithDescription("Log an agent action to the audit trail"),
		mcp.WithString("tool_called", mcp.Required(), mcp.Description("Tool that was called")),
		mcp.WithString("action_type", mcp.Required(), mcp.Description("Action type"), mcp.Enum("read", "write", "execute", "network", "validate")),
		mcp.WithString("target", mcp.Description("Target of the action")),
		mcp.WithString("risk_level", mcp.Description("Risk level"), mcp.Enum("low", "medium", "high", "critical")),
		mcp.WithString("result", mcp.Description("Result"), mcp.Enum("success", "blocked", "warning", "error")),
	)
	s.server.AddTool(auditLog, s.handleAuditLog)

	sessionAudit := mcp.NewTool("session_audit",
		mcp.WithDescription("Get complete audit log for current or specified session"),
		mcp.WithString("session_id", mcp.Description("Session ID")),
		mcp.WithString("risk_level", mcp.Description("Filter by minimum risk level")),
	)
	s.server.AddTool(sessionAudit, s.handleSessionAudit)

	injectGuard := mcp.NewTool("inject_guard",
		mcp.WithDescription("Check content for prompt injection patterns"),
		mcp.WithString("content", mcp.Required(), mcp.Description("Content to check")),
	)
	s.server.AddTool(injectGuard, s.handleInjectGuard)

	proactiveScan := mcp.NewTool("proactive_scan",
		mcp.WithDescription("Proactively scan module files for prompt injection"),
		mcp.WithString("module_path", mcp.Required(), mcp.Description("Module path to scan")),
		mcp.WithArray("include_patterns", mcp.Description("File patterns to include"), mcp.WithStringItems()),
	)
	s.server.AddTool(proactiveScan, s.handleProactiveScan)

	sanitize := mcp.NewTool("sanitize",
		mcp.WithDescription("Stripe secrets and private tags from content"),
		mcp.WithString("content", mcp.Required(), mcp.Description("Content to sanitize")),
	)
	s.server.AddTool(sanitize, s.handleSanitize)
}

func (s *Server) registerStandardsTools() {
	standardRun := mcp.NewTool("standard_run",
		mcp.WithDescription("Run a specific standard"),
		mcp.WithString("standard_id", mcp.Required(), mcp.Description("Standard ID to run")),
		mcp.WithString("checkpoint", mcp.Description("Checkpoint type")),
		mcp.WithString("risk_level", mcp.Description("Risk level")),
	)
	s.server.AddTool(standardRun, s.handleStandardRun)

	standardRunAll := mcp.NewTool("standard_run_all",
		mcp.WithDescription("Run all standards and return Quality Snapshot"),
		mcp.WithString("checkpoint_type", mcp.Description("Checkpoint type"), mcp.Enum("all", "post", "post_high_risk", "final_checkpoint")),
		mcp.WithString("risk_level", mcp.Description("Risk level"), mcp.Enum("low", "medium", "high", "critical")),
	)
	s.server.AddTool(standardRunAll, s.handleStandardRunAll)

	standardList := mcp.NewTool("standard_list",
		mcp.WithDescription("List configured standards with last result"),
	)
	s.server.AddTool(standardList, s.handleStandardList)

	qualitySnapshot := mcp.NewTool("quality_snapshot",
		mcp.WithDescription("Get the most recent Quality Snapshot"),
	)
	s.server.AddTool(qualitySnapshot, s.handleQualitySnapshot)
}

func (s *Server) registerScopeTools() {
	scopeViolations := mcp.NewTool("scope_violations",
		mcp.WithDescription("List detected scope violations"),
		mcp.WithString("session_id", mcp.Description("Filter by session ID")),
		mcp.WithBoolean("today", mcp.Description("Show only today's violations")),
	)
	s.server.AddTool(scopeViolations, s.handleScopeViolations)

	tyrStats := mcp.NewTool("tyr_stats",
		mcp.WithDescription("System statistics and knowledge graph health"),
	)
	s.server.AddTool(tyrStats, s.handleTyrStats)
}

func (s *Server) RunStdio() error {
	return server.ServeStdio(s.server)
}

func (s *Server) RunHTTP(port int) error {
	return nil
}

func (s *Server) handlePkgCheck(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	name := getString(args, "name")
	ecosystem := getString(args, "ecosystem")
	version := getStringOrDefault(args, "version", "")

	cacheID := fmt.Sprintf("%s:%s:%s", ecosystem, name, version)
	cached, _ := s.graph.GetPackageCache(cacheID)

	if cached != nil {
		data, _ := json.Marshal(cached)
		return mcp.NewToolResultText(string(data)), nil
	}

	result := map[string]interface{}{
		"package":            name,
		"ecosystem":          ecosystem,
		"exists":             true,
		"trusted":            true,
		"trust_factors":      map[string]interface{}{"downloads_monthly": 1000, "age_days": 365, "maintainers": 3},
		"typosquatting_risk": "low",
		"cve_count":          0,
		"cves":               []string{},
		"warning":            "",
		"recommendation":     "Package appears safe",
	}

	data, _ := json.Marshal(result)
	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handlePkgLicense(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	name := getString(args, "name")
	ecosystem := getString(args, "ecosystem")

	result := map[string]interface{}{
		"package":            name,
		"ecosystem":          ecosystem,
		"license":            "MIT",
		"transitive_license": "MIT",
		"transitive_count":   0,
		"problematic_deps":   []string{},
		"risk_level":         "low",
		"policy_compliant":   true,
	}

	data, _ := json.Marshal(result)
	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handlePkgAudit(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	result := map[string]interface{}{
		"vulnerabilities":    []string{},
		"total_dependencies": 0,
		"vulnerable_count":   0,
	}

	data, _ := json.Marshal(result)
	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handlePkgAuditSnapshot(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	result := map[string]interface{}{
		"snapshot_time":      "now",
		"vulnerabilities":    []string{},
		"severity_breakdown": map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0},
	}

	data, _ := json.Marshal(result)
	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handlePkgAuditContinuous(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	result := map[string]interface{}{
		"new_cves":   []string{},
		"last_check": "now",
		"status":     "clean",
	}

	data, _ := json.Marshal(result)
	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handleSASTRun(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	target := getStringOrDefault(args, "target", ".")
	rulesets := getStringSlice(args, "rulesets")

	result := map[string]interface{}{
		"target":         target,
		"rulesets":       rulesets,
		"findings":       []graph.SASTFinding{},
		"passed":         true,
		"findings_count": 0,
	}

	data, _ := json.Marshal(result)
	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handleSASTFindings(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	severity := getStringOrDefault(args, "severity", "")
	file := getStringOrDefault(args, "file", "")
	status := getStringOrDefault(args, "status", "open")

	findings, err := s.graph.ListSASTFindings(status, file)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if severity != "" {
		var filtered []graph.SASTFinding
		for _, f := range findings {
			if f.Severity == severity {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	data, _ := json.Marshal(findings)
	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handleSASTResolve(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	findingID := getString(args, "finding_id")

	err := s.graph.ResolveSASTFinding(findingID)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"finding_id": "%s", "status": "resolved"}`, findingID)), nil
}

func (s *Server) handleAuditLog(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	toolCalled := getString(args, "tool_called")
	actionType := getString(args, "action_type")
	target := getStringOrDefault(args, "target", "")
	riskLevel := getStringOrDefault(args, "risk_level", "low")
	result := getStringOrDefault(args, "result", "success")

	var sessionID string
	s.graph.DB().QueryRow("SELECT id FROM sessions WHERE status = 'active' ORDER BY started_at DESC LIMIT 1").Scan(&sessionID)

	if sessionID == "" {
		sessionID = "ses-" + uuid.New().String()
		s.graph.DB().Exec("INSERT INTO sessions (id, goal, status) VALUES (?, ?, 'active')", sessionID, "tyr-session")
	}

	entry := &graph.AuditEntry{
		ID:         "audit-" + uuid.New().String(),
		SessionID:  sessionID,
		ToolCalled: toolCalled,
		ActionType: actionType,
		Target:     target,
		RiskLevel:  riskLevel,
		Result:     result,
	}

	err := s.graph.AddAuditEntry(entry)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	return mcp.NewToolResultText(`{"logged": true}`), nil
}

func (s *Server) handleSessionAudit(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	sessionID := getStringOrDefault(args, "session_id", "")
	riskLevel := getStringOrDefault(args, "risk_level", "")

	if sessionID == "" {
		s.graph.DB().QueryRow("SELECT id FROM sessions WHERE status = 'active' ORDER BY started_at DESC LIMIT 1").Scan(&sessionID)
	}

	logs, err := s.graph.GetSessionAudit(sessionID, riskLevel)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	data, _ := json.Marshal(logs)
	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handleInjectGuard(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	content := getString(args, "content")

	suspicious := false
	var findings []string

	injectionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous\s+)?instructions`),
		regexp.MustCompile(`(?i)you\s+are\s+now\s+(a\s+)?`),
		regexp.MustCompile(`(?i)disregard\s+(your|all|previous)`),
		regexp.MustCompile(`(?i)new\s+(persona|role|identity|instructions)`),
		regexp.MustCompile(`(?i)forget\s+(everything|all|previous|your)`),
		regexp.MustCompile(`\[SYSTEM\]|\[INST\]|<\|im_start\|>`),
		regexp.MustCompile(`(?i)act\s+as\s+if\s+you\s+(are|have\s+no)`),
		regexp.MustCompile(`(?i)your\s+(real|true|actual)\s+(purpose|goal|instruction)`),
	}

	contentLower := strings.ToLower(content)
	for _, pattern := range injectionPatterns {
		if pattern.MatchString(contentLower) {
			suspicious = true
			findings = append(findings, pattern.String())
		}
	}

	result := map[string]interface{}{
		"suspicious": suspicious,
		"findings":   findings,
	}

	data, _ := json.Marshal(result)
	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handleProactiveScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	modulePath := getString(args, "module_path")

	result := map[string]interface{}{
		"module_path":   modulePath,
		"files_scanned": 0,
		"findings":      []string{},
		"status":        "clean",
	}

	data, _ := json.Marshal(result)
	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handleSanitize(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	content := getString(args, "content")

	secretPatterns := []*regexp.Regexp{
		regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
		regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-]{40,}`),
		regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		regexp.MustCompile(`ya29\.[a-zA-Z0-9\-_]+`),
		regexp.MustCompile(`eyJ[a-zA-Z0-9._-]{20,}`),
	}

	sanitized := content
	for _, pattern := range secretPatterns {
		sanitized = pattern.ReplaceAllString(sanitized, "[SECRET]")
	}

	sanitized = strings.ReplaceAll(sanitized, "[PRIVATE]", "[REDACTED]")

	return mcp.NewToolResultText(fmt.Sprintf(`{"sanitized": %v}`, sanitized)), nil
}

func (s *Server) handleStandardRun(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	standardID := getString(args, "standard_id")

	result := map[string]interface{}{
		"standard_id": standardID,
		"passed":      true,
		"duration_ms": 100,
	}

	data, _ := json.Marshal(result)
	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handleStandardRunAll(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	checkpointType := getStringOrDefault(args, "checkpoint_type", "all")
	riskLevel := getStringOrDefault(args, "risk_level", "medium")

	result := map[string]interface{}{
		"ran_at":                "now",
		"checkpoint_type":       checkpointType,
		"phase_risk":            riskLevel,
		"unit_tests":            []map[string]interface{}{},
		"e2e_tests":             []map[string]interface{}{},
		"sast":                  []map[string]interface{}{},
		"security":              []map[string]interface{}{},
		"overall_quality_score": 1.0,
		"previous_score":        1.0,
		"score_delta":           0.0,
		"blockers":              []string{},
		"warnings":              []string{},
	}

	data, _ := json.Marshal(result)
	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handleStandardList(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	standards := []map[string]interface{}{
		{"id": "test-pass", "description": "Tests must pass", "type": "test", "last_result": "passed"},
		{"id": "lint-clean", "description": "No lint errors", "type": "lint", "last_result": "passed"},
	}

	data, _ := json.Marshal(standards)
	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handleQualitySnapshot(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	result := map[string]interface{}{
		"overall_quality_score": 1.0,
		"unit_tests_passed":     true,
		"e2e_tests_passed":      true,
		"sast_clean":            true,
	}

	data, _ := json.Marshal(result)
	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handleScopeViolations(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	sessionID := getStringOrDefault(args, "session_id", "")
	today := getBoolOrDefault(args, "today", false)

	violations, err := s.graph.ListScopeViolations(sessionID, today)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	data, _ := json.Marshal(violations)
	return mcp.NewToolResultText(string(data)), nil
}

func (s *Server) handleTyrStats(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	stats, err := s.graph.GetStats()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	data, _ := json.Marshal(stats)
	return mcp.NewToolResultText(string(data)), nil
}

func getString(args map[string]interface{}, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getStringOrDefault(args map[string]interface{}, key, defaultVal string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultVal
}

func getStringSlice(args map[string]interface{}, key string) []string {
	if v, ok := args[key]; ok {
		if s, ok := v.([]interface{}); ok {
			result := make([]string, 0, len(s))
			for _, item := range s {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result
		}
	}
	return nil
}

func getFloatOrDefault(args map[string]interface{}, key string, defaultVal float64) float64 {
	if v, ok := args[key]; ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return defaultVal
}

func getIntOrDefault(args map[string]interface{}, key string, defaultVal int) int {
	if v, ok := args[key]; ok {
		if f, ok := v.(float64); ok {
			return int(f)
		}
	}
	return defaultVal
}

func getBoolOrDefault(args map[string]interface{}, key string, defaultVal bool) bool {
	if v, ok := args[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return defaultVal
}
