import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import "./Home.css";

export default function Home() {
  const { user } = useAuth();

  return (
    <div className="home">
      <section className="hero container">
        <div className="hero-badge">Autonomous Code Security Intelligence Engine</div>
        <h1>
          Detect vulnerabilities.
          <br />
          <span className="gradient-text">Understand &amp; fix them with AI.</span>
        </h1>
        <p className="hero-subtitle">
          NeuroShield combines OWASP Top 10 static analysis, CVE dependency scanning, and
          GPT-powered explanations into a single security dashboard — with professional PDF reports.
        </p>
        <div className="hero-actions">
          {user ? (
            <Link to="/upload" className="btn btn-primary btn-lg">
              Start Security Scan
            </Link>
          ) : (
            <>
              <Link to="/register" className="btn btn-primary btn-lg">
                Get Started
              </Link>
              <Link to="/login" className="btn btn-secondary btn-lg">
                Login
              </Link>
            </>
          )}
        </div>
      </section>

      <section className="features container">
        <div className="feature-card card">
          <div className="feature-icon">🔍</div>
          <h3>SAST Scanning</h3>
          <p>Bandit &amp; Semgrep detect OWASP Top 10 patterns in Python, JS, and Java code.</p>
        </div>
        <div className="feature-card card">
          <div className="feature-icon">📦</div>
          <h3>CVE Detection</h3>
          <p>Scans requirements.txt, package.json, and pom.xml against OSV.dev &amp; NVD databases.</p>
        </div>
        <div className="feature-card card">
          <div className="feature-icon">🤖</div>
          <h3>AI Remediation</h3>
          <p>GPT-4o-mini explains each finding, describes attack scenarios, and suggests code fixes.</p>
        </div>
        <div className="feature-card card">
          <div className="feature-icon">📄</div>
          <h3>PDF Reports</h3>
          <p>Download penetration-test-style reports with executive summaries and detailed findings.</p>
        </div>
      </section>
    </div>
  );
}
