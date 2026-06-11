import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { Finding, scanApi } from "../api/client";
import SeverityBadge from "../components/SeverityBadge";
import "./Dashboard.css";

export default function Dashboard() {
  const { sessionId } = useParams();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState({ critical: 0, high: 0, medium: 0, low: 0, total: 0 });
  const [filter, setFilter] = useState("");
  const [aiAvailable, setAiAvailable] = useState(true);
  const [reportAvailable, setReportAvailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [warnings, setWarnings] = useState<string[]>([]);

  useEffect(() => {
    if (!sessionId) return;
    const load = async () => {
      setLoading(true);
      try {
        const { data } = await scanApi.results(Number(sessionId), filter || undefined);
        setFindings(data.findings);
        setSummary(data.severity_summary);
        setAiAvailable(data.ai_available);
        setReportAvailable(data.report_available);
        setWarnings(data.scan_warnings || []);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [sessionId, filter]);

  const downloadReport = async () => {
    setDownloading(true);
    try {
      const { data } = await scanApi.downloadReport(Number(sessionId));
      const url = URL.createObjectURL(data);
      const a = document.createElement("a");
      a.href = url;
      a.download = `neuroshield_report_${sessionId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setDownloading(false);
    }
  };

  if (loading) return <div className="container page">Loading results...</div>;

  return (
    <div className="container page dashboard">
      <div className="dashboard-header">
        <div>
          <h1>Security Scan Results</h1>
          <p className="page-subtitle">Session #{sessionId}</p>
        </div>
        {reportAvailable && (
          <button className="btn btn-primary" onClick={downloadReport} disabled={downloading}>
            {downloading ? "Generating..." : "Download PDF Report"}
          </button>
        )}
      </div>

      {warnings.length > 0 && (
        <div className="error-banner">
          <strong>Scan warnings:</strong>
          <ul style={{ marginTop: "0.5rem", paddingLeft: "1.25rem" }}>
            {warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      {!aiAvailable && (
        <div className="info-banner">
          AI explanations are temporarily unavailable. SAST and CVE results are still shown. Refer to{" "}
          <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noreferrer">
            OWASP documentation
          </a>
          .
        </div>
      )}

      <div className="summary-grid">
        <SummaryCard label="Critical" count={summary.critical} color="critical" />
        <SummaryCard label="High" count={summary.high} color="high" />
        <SummaryCard label="Medium" count={summary.medium} color="medium" />
        <SummaryCard label="Low" count={summary.low} color="low" />
      </div>

      <div className="filter-bar">
        <label>Filter by severity:</label>
        <select value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="">All ({summary.total})</option>
          <option value="critical">Critical ({summary.critical})</option>
          <option value="high">High ({summary.high})</option>
          <option value="medium">Medium ({summary.medium})</option>
          <option value="low">Low ({summary.low})</option>
        </select>
      </div>

      {findings.length === 0 ? (
        <div className="card empty-state">
          <p>No vulnerabilities found matching your filter. Great job!</p>
        </div>
      ) : (
        <div className="findings-list">
          {findings.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}

function SummaryCard({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div className={`summary-card card ${color}`}>
      <span className="summary-count">{count}</span>
      <span className="summary-label">{label}</span>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="card finding-card">
      <div className="finding-header">
        <h3>{finding.title}</h3>
        <SeverityBadge severity={finding.severity} />
      </div>
      <div className="finding-meta">
        <span className="type-badge">{finding.finding_type.toUpperCase()}</span>
        {finding.file_path && (
          <span>
            {finding.file_path}
            {finding.line_number ? `:${finding.line_number}` : ""}
          </span>
        )}
        {finding.cve_id && (
          <span>
            {finding.cve_id} — {finding.package_name}@{finding.package_version}
            {finding.cvss_score != null && ` (CVSS: ${finding.cvss_score})`}
          </span>
        )}
        {finding.cwe_id && <span>{finding.cwe_id}</span>}
        {finding.category && <span>{finding.category}</span>}
      </div>
      {finding.description && <p className="finding-desc">{finding.description}</p>}
      {finding.code_snippet && (
        <pre className="code-snippet">{finding.code_snippet}</pre>
      )}
      {finding.ai_explanation && (
        <div className="ai-section">
          <h4>AI Explanation</h4>
          <p>{finding.ai_explanation}</p>
        </div>
      )}
      {finding.exploitation_scenario && (
        <div className="ai-section exploit">
          <h4>Exploitation Scenario</h4>
          <p>{finding.exploitation_scenario}</p>
        </div>
      )}
      {finding.fix_snippet && (
        <div className="ai-section fix">
          <h4>Recommended Fix</h4>
          <pre className="code-snippet">{finding.fix_snippet}</pre>
        </div>
      )}
    </div>
  );
}
