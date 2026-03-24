package graph

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Graph struct {
	db      *sql.DB
	dataDir string
}

func New(dataDir string) (*Graph, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "tyr.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(1)

	return &Graph{db: db, dataDir: dataDir}, nil
}

func (g *Graph) Init() error {
	schemas := []string{
		`CREATE TABLE IF NOT EXISTS pkg_cache (
			id TEXT PRIMARY KEY,
			ecosystem TEXT NOT NULL,
			name TEXT NOT NULL,
			version TEXT,
			exists_pkg INTEGER NOT NULL,
			trusted INTEGER DEFAULT 1,
			cve_count INTEGER DEFAULT 0,
			license TEXT,
			transitive_license_risk TEXT DEFAULT 'none',
			downloads INTEGER DEFAULT 0,
			age_days INTEGER DEFAULT 0,
			response TEXT,
			cached_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS sast_findings (
			id TEXT PRIMARY KEY,
			session_id TEXT,
			rule_id TEXT NOT NULL,
			file TEXT NOT NULL,
			line INTEGER,
			message TEXT NOT NULL,
			severity TEXT NOT NULL,
			owasp TEXT,
			cwe TEXT,
			status TEXT DEFAULT 'open',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			resolved_at DATETIME
		)`,

		`CREATE TABLE IF NOT EXISTS audit_log (
			id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL,
			tool_called TEXT NOT NULL,
			action_type TEXT NOT NULL,
			target TEXT,
			risk_level TEXT DEFAULT 'low',
			result TEXT DEFAULT 'success',
			metadata TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS standards_results (
			id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL,
			standard_id TEXT NOT NULL,
			checkpoint TEXT,
			passed INTEGER NOT NULL,
			metric_value REAL,
			output TEXT,
			duration_ms INTEGER,
			ran_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS scope_violations (
			id TEXT PRIMARY KEY,
			session_id TEXT,
			file TEXT NOT NULL,
			agent TEXT,
			operation TEXT NOT NULL,
			reverted INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS cve_alerts (
			id TEXT PRIMARY KEY,
			package_id TEXT NOT NULL,
			cve_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			summary TEXT,
			detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			acknowledged INTEGER DEFAULT 0
		)`,

		`CREATE TABLE IF NOT EXISTS meta (
			key TEXT PRIMARY KEY,
			value TEXT
		)`,
	}

	for _, schema := range schemas {
		if _, err := g.db.Exec(schema); err != nil {
			return fmt.Errorf("failed to create schema: %w", err)
		}
	}

	if _, err := g.db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	if _, err := g.db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	indices := []string{
		"CREATE INDEX IF NOT EXISTS idx_pkg_cache_expires ON pkg_cache(expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_sast_findings_status ON sast_findings(status)",
		"CREATE INDEX IF NOT EXISTS idx_sast_findings_file ON sast_findings(file)",
		"CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id)",
		"CREATE INDEX IF NOT EXISTS idx_audit_risk ON audit_log(risk_level)",
		"CREATE INDEX IF NOT EXISTS idx_standards_session ON standards_results(session_id)",
		"CREATE INDEX IF NOT EXISTS idx_scope_violations_session ON scope_violations(session_id)",
		"CREATE INDEX IF NOT EXISTS idx_cve_alerts_package ON cve_alerts(package_id)",
	}

	for _, idx := range indices {
		if _, err := g.db.Exec(idx); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

func (g *Graph) Close() error {
	return g.db.Close()
}

func (g *Graph) DB() *sql.DB {
	return g.db
}

type PackageCache struct {
	ID                    string    `json:"id"`
	Ecosystem             string    `json:"ecosystem"`
	Name                  string    `json:"name"`
	Version               string    `json:"version,omitempty"`
	Exists                bool      `json:"exists"`
	Trusted               bool      `json:"trusted"`
	CveCount              int       `json:"cve_count"`
	License               string    `json:"license,omitempty"`
	TransitiveLicenseRisk string    `json:"transitive_license_risk"`
	Downloads             int       `json:"downloads"`
	AgeDays               int       `json:"age_days"`
	Response              string    `json:"response,omitempty"`
	CachedAt              time.Time `json:"cached_at"`
	ExpiresAt             time.Time `json:"expires_at"`
}

func (g *Graph) SavePackageCache(pkg *PackageCache) error {
	_, err := g.db.Exec(`
		INSERT OR REPLACE INTO pkg_cache (id, ecosystem, name, version, exists_pkg, trusted, cve_count, license, transitive_license_risk, downloads, age_days, response, cached_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)
	`, pkg.ID, pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Exists, pkg.Trusted, pkg.CveCount, pkg.License, pkg.TransitiveLicenseRisk, pkg.Downloads, pkg.AgeDays, pkg.Response, pkg.ExpiresAt)
	return err
}

func (g *Graph) GetPackageCache(id string) (*PackageCache, error) {
	var pkg PackageCache
	err := g.db.QueryRow(`
		SELECT id, ecosystem, name, version, exists_pkg, trusted, cve_count, license, transitive_license_risk, downloads, age_days, response, cached_at, expires_at
		FROM pkg_cache WHERE id = ? AND expires_at > datetime('now')
	`, id).Scan(&pkg.ID, &pkg.Ecosystem, &pkg.Name, &pkg.Version, &pkg.Exists, &pkg.Trusted, &pkg.CveCount, &pkg.License, &pkg.TransitiveLicenseRisk, &pkg.Downloads, &pkg.AgeDays, &pkg.Response, &pkg.CachedAt, &pkg.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &pkg, nil
}

type SASTFinding struct {
	ID         string     `json:"id"`
	SessionID  string     `json:"session_id,omitempty"`
	RuleID     string     `json:"rule_id"`
	File       string     `json:"file"`
	Line       int        `json:"line,omitempty"`
	Message    string     `json:"message"`
	Severity   string     `json:"severity"`
	OWASP      string     `json:"owasp,omitempty"`
	CWE        string     `json:"cwe,omitempty"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

func (g *Graph) SaveSASTFinding(finding *SASTFinding) error {
	_, err := g.db.Exec(`
		INSERT INTO sast_findings (id, session_id, rule_id, file, line, message, severity, owasp, cwe, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, finding.ID, finding.SessionID, finding.RuleID, finding.File, finding.Line, finding.Message, finding.Severity, finding.OWASP, finding.CWE, finding.Status)
	return err
}

func (g *Graph) ListSASTFindings(status, file string) ([]SASTFinding, error) {
	query := "SELECT id, session_id, rule_id, file, line, message, severity, owasp, cwe, status, created_at, resolved_at FROM sast_findings WHERE 1=1"
	args := []interface{}{}

	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	if file != "" {
		query += " AND file = ?"
		args = append(args, file)
	}
	query += " ORDER BY created_at DESC"

	rows, err := g.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []SASTFinding
	for rows.Next() {
		var f SASTFinding
		err := rows.Scan(&f.ID, &f.SessionID, &f.RuleID, &f.File, &f.Line, &f.Message, &f.Severity, &f.OWASP, &f.CWE, &f.Status, &f.CreatedAt, &f.ResolvedAt)
		if err != nil {
			continue
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func (g *Graph) ResolveSASTFinding(id string) error {
	_, err := g.db.Exec(`UPDATE sast_findings SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
	return err
}

type AuditEntry struct {
	ID         string    `json:"id"`
	SessionID  string    `json:"session_id"`
	ToolCalled string    `json:"tool_called"`
	ActionType string    `json:"action_type"`
	Target     string    `json:"target,omitempty"`
	RiskLevel  string    `json:"risk_level"`
	Result     string    `json:"result"`
	Metadata   string    `json:"metadata,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

func (g *Graph) AddAuditEntry(entry *AuditEntry) error {
	_, err := g.db.Exec(`
		INSERT INTO audit_log (id, session_id, tool_called, action_type, target, risk_level, result, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, entry.ID, entry.SessionID, entry.ToolCalled, entry.ActionType, entry.Target, entry.RiskLevel, entry.Result, entry.Metadata)
	return err
}

func (g *Graph) GetSessionAudit(sessionID, riskLevel string) ([]AuditEntry, error) {
	query := "SELECT id, session_id, tool_called, action_type, target, risk_level, result, metadata, created_at FROM audit_log WHERE session_id = ?"
	args := []interface{}{sessionID}

	if riskLevel != "" {
		query += " AND risk_level >= ?"
		args = append(args, riskLevel)
	}
	query += " ORDER BY created_at DESC LIMIT 100"

	rows, err := g.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		err := rows.Scan(&e.ID, &e.SessionID, &e.ToolCalled, &e.ActionType, &e.Target, &e.RiskLevel, &e.Result, &e.Metadata, &e.CreatedAt)
		if err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

type StandardsResult struct {
	ID          string    `json:"id"`
	SessionID   string    `json:"session_id"`
	StandardID  string    `json:"standard_id"`
	Checkpoint  string    `json:"checkpoint,omitempty"`
	Passed      bool      `json:"passed"`
	MetricValue float64   `json:"metric_value,omitempty"`
	Output      string    `json:"output,omitempty"`
	DurationMs  int       `json:"duration_ms,omitempty"`
	RanAt       time.Time `json:"ran_at"`
}

func (g *Graph) SaveStandardsResult(result *StandardsResult) error {
	_, err := g.db.Exec(`
		INSERT INTO standards_results (id, session_id, standard_id, checkpoint, passed, metric_value, output, duration_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, result.ID, result.SessionID, result.StandardID, result.Checkpoint, result.Passed, result.MetricValue, result.Output, result.DurationMs)
	return err
}

func (g *Graph) GetStandardsResults(sessionID string) ([]StandardsResult, error) {
	rows, err := g.db.Query(`
		SELECT id, session_id, standard_id, checkpoint, passed, metric_value, output, duration_ms, ran_at
		FROM standards_results WHERE session_id = ? ORDER BY ran_at DESC
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []StandardsResult
	for rows.Next() {
		var r StandardsResult
		err := rows.Scan(&r.ID, &r.SessionID, &r.StandardID, &r.Checkpoint, &r.Passed, &r.MetricValue, &r.Output, &r.DurationMs, &r.RanAt)
		if err != nil {
			continue
		}
		results = append(results, r)
	}
	return results, nil
}

type ScopeViolation struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id,omitempty"`
	File      string    `json:"file"`
	Agent     string    `json:"agent,omitempty"`
	Operation string    `json:"operation"`
	Reverted  bool      `json:"reverted"`
	CreatedAt time.Time `json:"created_at"`
}

func (g *Graph) SaveScopeViolation(violation *ScopeViolation) error {
	_, err := g.db.Exec(`
		INSERT INTO scope_violations (id, session_id, file, agent, operation, reverted)
		VALUES (?, ?, ?, ?, ?, ?)
	`, violation.ID, violation.SessionID, violation.File, violation.Agent, violation.Operation, violation.Reverted)
	return err
}

func (g *Graph) ListScopeViolations(sessionID string, today bool) ([]ScopeViolation, error) {
	query := "SELECT id, session_id, file, agent, operation, reverted, created_at FROM scope_violations WHERE 1=1"
	args := []interface{}{}

	if sessionID != "" {
		query += " AND session_id = ?"
		args = append(args, sessionID)
	}
	if today {
		query += " AND date(created_at) = date('now')"
	}
	query += " ORDER BY created_at DESC"

	rows, err := g.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var violations []ScopeViolation
	for rows.Next() {
		var v ScopeViolation
		err := rows.Scan(&v.ID, &v.SessionID, &v.File, &v.Agent, &v.Operation, &v.Reverted, &v.CreatedAt)
		if err != nil {
			continue
		}
		violations = append(violations, v)
	}
	return violations, nil
}

func (g *Graph) GetStats() (map[string]interface{}, error) {
	var pkgCount, sastCount, auditCount, standardsCount int

	g.db.QueryRow("SELECT COUNT(*) FROM pkg_cache WHERE expires_at > datetime('now')").Scan(&pkgCount)
	g.db.QueryRow("SELECT COUNT(*) FROM sast_findings WHERE status = 'open'").Scan(&sastCount)
	g.db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&auditCount)
	g.db.QueryRow("SELECT COUNT(*) FROM standards_results").Scan(&standardsCount)

	return map[string]interface{}{
		"packages_cached": pkgCount,
		"sast_findings":   sastCount,
		"audit_entries":   auditCount,
		"standards_runs":  standardsCount,
	}, nil
}
