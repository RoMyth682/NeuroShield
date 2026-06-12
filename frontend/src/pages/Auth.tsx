import { FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import "./Auth.css";

export function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(email, password);
      navigate("/home");
    } catch {
      setError("Invalid email or password. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-fullscreen">
      {/* Animated background orbs */}
      <div className="auth-bg-orb orb-1" />
      <div className="auth-bg-orb orb-2" />
      <div className="auth-bg-orb orb-3" />

      <div className="auth-card-wrapper">
        {/* Project Branding */}
        <div className="auth-brand">
          <div className="auth-brand-logo">
            <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
              <path
                d="M20 3L4 10v10c0 9.4 6.8 18.2 16 20.4C29.2 38.2 36 29.4 36 20V10L20 3z"
                fill="url(#shieldGrad)"
                stroke="rgba(139,92,246,0.5)"
                strokeWidth="1"
              />
              <path d="M14 20l4 4 8-8" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
              <defs>
                <linearGradient id="shieldGrad" x1="4" y1="3" x2="36" y2="40" gradientUnits="userSpaceOnUse">
                  <stop stopColor="#8b5cf6" />
                  <stop offset="1" stopColor="#3b82f6" />
                </linearGradient>
              </defs>
            </svg>
          </div>
          <h1 className="auth-brand-name">NeuroShield</h1>
          <p className="auth-brand-tagline">Autonomous Code Security Intelligence Engine</p>
        </div>

        {/* Login Card */}
        <div className="auth-card">
          <div className="auth-card-header">
            <h2 className="auth-card-title">Welcome back</h2>
            <p className="auth-card-subtitle">Sign in to your security dashboard</p>
          </div>

          {error && <div className="error-banner">{error}</div>}

          <form onSubmit={handleSubmit} className="auth-form">
            <div className="form-group">
              <label htmlFor="login-email">Email</label>
              <input
                id="login-email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
              />
            </div>
            <div className="form-group">
              <label htmlFor="login-password">Password</label>
              <input
                id="login-password"
                type="password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <button type="submit" className="btn btn-primary btn-full auth-submit-btn" disabled={loading}>
              {loading ? <span className="auth-spinner" /> : "Sign In"}
            </button>
          </form>

          <p className="auth-footer">
            Don&apos;t have an account? <Link to="/register">Register</Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await register(email, password);
      navigate("/home");
    } catch {
      setError("Registration failed. Email may already be in use.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-fullscreen">
      <div className="auth-bg-orb orb-1" />
      <div className="auth-bg-orb orb-2" />
      <div className="auth-bg-orb orb-3" />

      <div className="auth-card-wrapper">
        {/* Project Branding */}
        <div className="auth-brand">
          <div className="auth-brand-logo">
            <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
              <path
                d="M20 3L4 10v10c0 9.4 6.8 18.2 16 20.4C29.2 38.2 36 29.4 36 20V10L20 3z"
                fill="url(#shieldGrad2)"
                stroke="rgba(139,92,246,0.5)"
                strokeWidth="1"
              />
              <path d="M14 20l4 4 8-8" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
              <defs>
                <linearGradient id="shieldGrad2" x1="4" y1="3" x2="36" y2="40" gradientUnits="userSpaceOnUse">
                  <stop stopColor="#8b5cf6" />
                  <stop offset="1" stopColor="#3b82f6" />
                </linearGradient>
              </defs>
            </svg>
          </div>
          <h1 className="auth-brand-name">NeuroShield</h1>
          <p className="auth-brand-tagline">Autonomous Code Security Intelligence Engine</p>
        </div>

        {/* Register Card */}
        <div className="auth-card">
          <div className="auth-card-header">
            <h2 className="auth-card-title">Create Account</h2>
            <p className="auth-card-subtitle">Register to start scanning your code</p>
          </div>

          {error && <div className="error-banner">{error}</div>}

          <form onSubmit={handleSubmit} className="auth-form">
            <div className="form-group">
              <label htmlFor="reg-email">Email</label>
              <input
                id="reg-email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
              />
            </div>
            <div className="form-group">
              <label htmlFor="reg-password">Password <span className="auth-label-hint">(min 6 characters)</span></label>
              <input
                id="reg-password"
                type="password"
                placeholder="Create a password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                minLength={6}
                required
              />
            </div>
            <button type="submit" className="btn btn-primary btn-full auth-submit-btn" disabled={loading}>
              {loading ? <span className="auth-spinner" /> : "Create Account"}
            </button>
          </form>

          <p className="auth-footer">
            Already have an account? <Link to="/login">Sign In</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
