import { useEffect, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { scanApi } from "../api/client";
import "./Analysis.css";

const STAGES = [
  { key: "pending", label: "Queued" },
  { key: "sast_running", label: "SAST Scan" },
  { key: "cve_running", label: "CVE Scan" },
  { key: "ai_running", label: "AI Analysis" },
  { key: "completed", label: "Complete" },
];

export default function Analysis() {
  const { sessionId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as { files?: string[]; filename?: string } | null;

  const [status, setStatus] = useState("pending");
  const [message, setMessage] = useState("Starting analysis...");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!sessionId) return;
    const id = Number(sessionId);

    const poll = async () => {
      try {
        const { data } = await scanApi.status(id);
        setStatus(data.status);
        setMessage(data.message);
        if (data.error_message) setError(data.error_message);

        if (data.status === "completed") {
          navigate(`/results/${id}`, { replace: true });
        } else if (data.status === "failed") {
          setError(data.error_message || "Analysis failed");
        }
      } catch {
        setError("Failed to fetch analysis status");
      }
    };

    poll();
    const interval = setInterval(poll, 2000);
    return () => clearInterval(interval);
  }, [sessionId, navigate]);

  const currentIndex = STAGES.findIndex((s) => s.key === status);

  return (
    <div className="container page">
      <h1>Analysis in Progress</h1>
      <p className="page-subtitle">
        Scanning <strong>{state?.filename || "uploaded code"}</strong>
      </p>

      {error && <div className="error-banner">{error}</div>}

      <div className="card progress-card">
        <div className="stages">
          {STAGES.map((stage, i) => (
            <div
              key={stage.key}
              className={`stage ${i <= currentIndex ? "active" : ""} ${i === currentIndex ? "current" : ""}`}
            >
              <div className="stage-dot">{i < currentIndex ? "✓" : i + 1}</div>
              <span>{stage.label}</span>
            </div>
          ))}
        </div>
        <div className="progress-bar">
          <div
            className="progress-fill"
            style={{ width: `${Math.max(10, ((currentIndex + 1) / STAGES.length) * 100)}%` }}
          />
        </div>
        <p className="progress-message">{message}</p>
      </div>

      {state?.files && state.files.length > 0 && (
        <div className="card file-list-card">
          <h3>Uploaded Files ({state.files.length})</h3>
          <ul>
            {state.files.slice(0, 20).map((f) => (
              <li key={f}>{f}</li>
            ))}
            {state.files.length > 20 && <li>...and {state.files.length - 20} more</li>}
          </ul>
        </div>
      )}
    </div>
  );
}
