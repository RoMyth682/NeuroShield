import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { Finding, scanApi, ChatMessage } from "../api/client";
import SeverityBadge from "../components/SeverityBadge";
import "./Dashboard.css";

export default function Dashboard() {
  const { sessionId } = useParams();
  const [allFindings, setAllFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState({ critical: 0, high: 0, medium: 0, low: 0, total: 0 });
  const [filter, setFilter] = useState("");
  const [aiAvailable, setAiAvailable] = useState(true);
  const [reportAvailable, setReportAvailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [warnDismissed, setWarnDismissed] = useState(false);

  // Always load the full unfiltered list once — used for Top 3 and the filtered view
  useEffect(() => {
    if (!sessionId) return;
    const load = async () => {
      setLoading(true);
      try {
        const { data } = await scanApi.results(Number(sessionId));
        setAllFindings(data.findings);
        setSummary(data.severity_summary);
        setAiAvailable(data.ai_available);
        setReportAvailable(data.report_available);
        setWarnings(data.scan_warnings || []);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [sessionId]);

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

  const handleExplain = async (findingId: number) => {
    const { data } = await scanApi.explainFinding(findingId);
    setAllFindings((prev) => prev.map((f) => (f.id === findingId ? data : f)));
  };

  const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

  const top3 = useMemo(
    () =>
      [...allFindings]
        .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4))
        .slice(0, 3),
    [allFindings]
  );

  const filteredFindings = useMemo(
    () => (filter ? allFindings.filter((f) => f.severity === filter) : []),
    [allFindings, filter]
  );

  if (loading) return <div className="container page">Loading results...</div>;

  return (
    <div className="container page dashboard">
      {/* Header */}
      <div className="dashboard-header">
        <div>
          <h1>Security Scan Results</h1>
          <p className="page-subtitle">Session #{sessionId}</p>
        </div>
        {reportAvailable && (
          <button className="btn btn-primary" onClick={downloadReport} disabled={downloading}>
            {downloading ? "Generating..." : "⬇ Download PDF Report"}
          </button>
        )}
      </div>

      {/* Dismissible scan warning */}
      {!warnDismissed && warnings.length > 0 && (
        <div className="warn-banner">
          <div className="warn-banner-body">
            <span className="warn-icon">⚠️</span>
            <div>
              <strong>Scan warnings</strong>
              <ul>
                {warnings.map((w) => <li key={w}>{w}</li>)}
              </ul>
            </div>
          </div>
          <button className="warn-dismiss" onClick={() => setWarnDismissed(true)} title="Dismiss">✕</button>
        </div>
      )}

      {!aiAvailable && (
        <div className="info-banner">
          AI explanations unavailable — add an API key in{" "}
          <a href="/settings">⚙️ Settings</a>.
        </div>
      )}

      {/* Severity summary */}
      <div className="summary-grid">
        <SummaryCard label="Critical" count={summary.critical} color="critical" />
        <SummaryCard label="High"     count={summary.high}     color="high"     />
        <SummaryCard label="Medium"   count={summary.medium}   color="medium"   />
        <SummaryCard label="Low"      count={summary.low}      color="low"      />
      </div>

      {/* ── Top 3 (default view, no filter) ── */}
      {!filter && top3.length > 0 && (
        <div className="top3-section">
          <div className="top3-header">
            <span className="top3-icon">🔥</span>
            <div>
              <h2 className="top3-title">Top 3 Most Critical Vulnerabilities</h2>
              <p className="top3-subtitle">Highest-priority findings requiring immediate attention</p>
            </div>
          </div>
          <div className="top3-list">
            {top3.map((f, i) => (
              <div key={f.id} className={`top3-card card severity-${f.severity}`}>
                <div className="top3-rank">#{i + 1}</div>
                <div className="top3-body">
                  <FindingCard finding={f} onExplain={handleExplain} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Filter bar — browsing all findings ── */}
      <div className="filter-bar">
        <span className="filter-label">Browse all {summary.total} findings by severity:</span>
        <select value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="">— Select a filter —</option>
          <option value="critical">🔴 Critical ({summary.critical})</option>
          <option value="high">🟠 High ({summary.high})</option>
          <option value="medium">🟡 Medium ({summary.medium})</option>
          <option value="low">🟢 Low ({summary.low})</option>
        </select>
        {filter && (
          <button className="clear-filter-btn" onClick={() => setFilter("")}>✕ Clear filter</button>
        )}
      </div>

      {/* ── Filtered findings list ── */}
      {filter && (
        <>
          <div className="section-divider">
            <span>{filter.charAt(0).toUpperCase() + filter.slice(1)} Findings ({filteredFindings.length})</span>
          </div>
          {filteredFindings.length === 0 ? (
            <div className="card empty-state">
              <p>No {filter} severity findings. 🎉</p>
            </div>
          ) : (
            <div className="findings-list">
              {filteredFindings.map((f) => (
                <FindingCard key={f.id} finding={f} onExplain={handleExplain} />
              ))}
            </div>
          )}
        </>
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


function FindingCard({ finding, onExplain, compact = false }: { finding: Finding; onExplain: (id: number) => Promise<void>; compact?: boolean }) {
  const [loading, setLoading] = useState(false);
  const [chatHistory, setChatHistory] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);

  const handleExplainClick = async () => {
    setLoading(true);
    try {
      await onExplain(finding.id);
    } catch (err) {
      console.error("Failed to explain finding:", err);
      alert("Failed to generate AI explanation. Please check backend logs/API key config.");
    } finally {
      setLoading(false);
    }
  };

  const handleSendChat = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim() || chatLoading) return;

    const userMsg: ChatMessage = { role: "user", content: chatInput };
    setChatHistory((prev) => [...prev, userMsg]);
    const currentInput = chatInput;
    setChatInput("");
    setChatLoading(true);

    try {
      const { data } = await scanApi.chatFinding(finding.id, currentInput, chatHistory);
      const aiMsg: ChatMessage = { role: "assistant", content: data.message };
      setChatHistory((prev) => [...prev, aiMsg]);
    } catch (err) {
      console.error("Chat error:", err);
      alert("Failed to get response from AI Chatbot.");
    } finally {
      setChatLoading(false);
    }
  };

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
      {(finding.ai_explanation || finding.exploitation_scenario || finding.fix_snippet) ? (
        <div className="ai-container">
          <div className="ai-container-header">
            <span className="ai-badge">🤖 AI Remediation Insights</span>
            {/* Show retry button if explanation is a fallback error */}
            {finding.ai_explanation?.startsWith("⚠️") && (
              <button
                className="ai-retry-btn"
                onClick={handleExplainClick}
                disabled={loading}
                title="Retry AI analysis"
              >
                {loading ? <><span className="spinner-small" /> Retrying…</> : <>🔄 Retry AI</>}
              </button>
            )}
          </div>
          {finding.ai_explanation && (
            <div className={`ai-section ${finding.ai_explanation.startsWith("⚠️") ? "ai-fallback" : ""}`}>
              <h4>Vulnerability Analysis</h4>
              <p style={{ whiteSpace: "pre-wrap" }}>{finding.ai_explanation}</p>
            </div>
          )}
          {finding.exploitation_scenario && (
            <div className="ai-section exploit">
              <h4>Exploitation Scenario</h4>
              <p style={{ whiteSpace: "pre-wrap" }}>{finding.exploitation_scenario}</p>
            </div>
          )}
          {finding.fix_snippet && (
            <div className="ai-section fix">
              <h4>Suggested Remediation</h4>
              <pre className="code-snippet fix-code">{finding.fix_snippet}</pre>
            </div>
          )}

          {/* Follow-up chat UI */}
          <div className="ai-chat-section">
            <h4>💬 Ask AI Assistant</h4>
            <div className="ai-chat-history">
              {chatHistory.length === 0 && (
                <div className="chat-message assistant">
                  <em>Ask any question about this vulnerability, how to exploit/prevent it, or how to fix it in Spring/Django/etc.</em>
                </div>
              )}
              {chatHistory.map((msg, i) => (
                <div key={i} className={`chat-message ${msg.role}`}>
                  <strong>{msg.role === "user" ? "You" : "AI"}:</strong> {msg.content}
                </div>
              ))}
              {chatLoading && (
                <div className="chat-message assistant typing">
                  <strong>AI:</strong> <span className="typing-dots"><span>.</span><span>.</span><span>.</span></span>
                </div>
              )}
            </div>
            <form onSubmit={handleSendChat} className="ai-chat-form">
              <input
                type="text"
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                placeholder="Ask follow-up question..."
                disabled={chatLoading}
              />
              <button type="submit" className="btn btn-primary btn-sm" disabled={chatLoading}>
                Send
              </button>
            </form>
          </div>
        </div>
      ) : (
        <div className="ai-trigger-container">
          <button 
            className="ai-explain-btn" 
            onClick={handleExplainClick} 
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="spinner-small"></span> Analyzing finding...
              </>
            ) : (
              <>✨ Explain with AI</>
            )}
          </button>
        </div>
      )}
    </div>
  );
}
