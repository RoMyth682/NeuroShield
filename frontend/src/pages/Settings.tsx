import { useEffect, useState } from "react";
import { AIModel, AISettingsResponse, settingsApi } from "../api/client";
import "./Settings.css";

const PROVIDER_LABELS: Record<string, { label: string; icon: string; color: string }> = {
  groq:   { label: "Groq",    icon: "⚡", color: "#f97316" },
  openai: { label: "OpenAI",  icon: "🤖", color: "#10b981" },
  gemini: { label: "Gemini",  icon: "✨", color: "#8b5cf6" },
  none:   { label: "None",    icon: "❌", color: "#6b7280" },
};

export default function Settings() {
  const [cfg, setCfg] = useState<AISettingsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  // editable fields
  const [groqKey, setGroqKey] = useState("");
  const [openaiKey, setOpenaiKey] = useState("");
  const [geminiKey, setGeminiKey] = useState("");
  const [groqModel, setGroqModel] = useState("");
  const [openaiModel, setOpenaiModel] = useState("");

  useEffect(() => {
    load();
  }, []);

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const { data } = await settingsApi.get();
      setCfg(data);
      setGroqModel(data.active_provider === "groq" ? data.active_model : data.groq_models[0]?.id ?? "");
      setOpenaiModel(data.active_provider === "openai" ? data.active_model : data.openai_models[0]?.id ?? "");
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? "Failed to load settings. Admin access required.");
    } finally {
      setLoading(false);
    }
  };

  const save = async () => {
    setSaving(true);
    setError("");
    try {
      const patch: any = {};
      if (groqKey)    patch.groq_api_key   = groqKey;
      if (openaiKey)  patch.openai_api_key = openaiKey;
      if (geminiKey)  patch.gemini_api_key = geminiKey;
      if (groqModel)  patch.groq_model     = groqModel;
      if (openaiModel) patch.openai_model  = openaiModel;

      const { data } = await settingsApi.update(patch);
      setCfg(data);
      setGroqKey("");
      setOpenaiKey("");
      setGeminiKey("");
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? "Failed to save settings.");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="container page">
        <div className="settings-loading">
          <div className="settings-spinner" />
          <span>Loading AI settings…</span>
        </div>
      </div>
    );
  }

  if (error && !cfg) {
    return (
      <div className="container page">
        <div className="error-banner" style={{ marginTop: "2rem" }}>{error}</div>
      </div>
    );
  }

  const provider = cfg?.active_provider ?? "none";
  const providerInfo = PROVIDER_LABELS[provider] ?? PROVIDER_LABELS.none;

  const allModels: AIModel[] = [
    ...(cfg?.groq_models ?? []),
    ...(cfg?.openai_models ?? []),
    ...(cfg?.gemini_models ?? []),
  ];

  return (
    <div className="container page settings-page">
      <div className="settings-hero">
        <div>
          <h1 className="settings-title">⚙️ AI Settings</h1>
          <p className="settings-subtitle">Configure your AI provider, API keys, and model selection</p>
        </div>
        {saved && <div className="saved-badge">✅ Saved successfully</div>}
      </div>

      {error && <div className="error-banner">{error}</div>}

      {/* Active Status Card */}
      <div className="settings-status-card card">
        <div className="status-row">
          <div className="status-indicator">
            <span className="status-dot" style={{ background: providerInfo.color }} />
            <span className="status-label">Active Provider</span>
          </div>
          <div className="status-value">
            <span className="provider-icon">{providerInfo.icon}</span>
            <span className="provider-name" style={{ color: providerInfo.color }}>
              {providerInfo.label}
            </span>
          </div>
        </div>
        <div className="status-row">
          <span className="status-label">Active Model</span>
          <span className="model-chip">{cfg?.active_model ?? "—"}</span>
        </div>
        <p className="status-note">
          Priority: Groq → Gemini → OpenAI. Only the first configured provider is used.
        </p>
      </div>

      {/* Model Selector */}
      <div className="settings-section card">
        <h2 className="section-title">🎯 Model Selection</h2>
        <p className="section-desc">Choose which model to use for AI explanations and chat. Changes take effect immediately — no restart needed.</p>

        <div className="model-tabs">
          {/* Groq Models */}
          <div className="model-group">
            <div className="model-group-header">
              <span className="provider-pill groq">⚡ Groq Models</span>
              <span className="provider-hint">Free — Ultra-fast inference</span>
            </div>
            <div className="model-grid">
              {(cfg?.groq_models ?? []).map((m) => (
                <label
                  key={m.id}
                  className={`model-card ${groqModel === m.id ? "selected" : ""} ${provider !== "groq" ? "inactive-provider" : ""}`}
                >
                  <input
                    type="radio"
                    name="groq_model"
                    value={m.id}
                    checked={groqModel === m.id}
                    onChange={() => setGroqModel(m.id)}
                  />
                  <div className="model-card-body">
                    <span className="model-name">{m.name}</span>
                    <span className="model-id">{m.id}</span>
                  </div>
                  {groqModel === m.id && provider === "groq" && (
                    <span className="model-active-badge">Active</span>
                  )}
                </label>
              ))}
            </div>
          </div>

          {/* OpenAI Models */}
          <div className="model-group">
            <div className="model-group-header">
              <span className="provider-pill openai">🤖 OpenAI Models</span>
              <span className="provider-hint">Paid — GPT series</span>
            </div>
            <div className="model-grid">
              {(cfg?.openai_models ?? []).map((m) => (
                <label
                  key={m.id}
                  className={`model-card ${openaiModel === m.id ? "selected" : ""} ${provider !== "openai" ? "inactive-provider" : ""}`}
                >
                  <input
                    type="radio"
                    name="openai_model"
                    value={m.id}
                    checked={openaiModel === m.id}
                    onChange={() => setOpenaiModel(m.id)}
                  />
                  <div className="model-card-body">
                    <span className="model-name">{m.name}</span>
                    <span className="model-id">{m.id}</span>
                  </div>
                  {openaiModel === m.id && provider === "openai" && (
                    <span className="model-active-badge">Active</span>
                  )}
                </label>
              ))}
            </div>
          </div>

          {/* Gemini Models */}
          <div className="model-group">
            <div className="model-group-header">
              <span className="provider-pill gemini">✨ Gemini Models</span>
              <span className="provider-hint">Free tier available</span>
            </div>
            <div className="model-grid">
              {(cfg?.gemini_models ?? []).map((m) => (
                <label
                  key={m.id}
                  className={`model-card inactive-provider`}
                >
                  <input type="radio" name="gemini_model" value={m.id} disabled />
                  <div className="model-card-body">
                    <span className="model-name">{m.name}</span>
                    <span className="model-id">{m.id}</span>
                  </div>
                  {provider === "gemini" && cfg?.active_model === m.id && (
                    <span className="model-active-badge">Active</span>
                  )}
                </label>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* API Keys */}
      <div className="settings-section card">
        <h2 className="section-title">🔑 API Keys</h2>
        <p className="section-desc">Enter a new key to update it. Existing keys are shown masked. Leave blank to keep unchanged.</p>

        <div className="keys-grid">
          {/* Groq */}
          <div className="key-card groq-card">
            <div className="key-header">
              <span className="provider-pill groq">⚡ Groq</span>
              {cfg?.groq_api_key
                ? <span className="key-status configured">Configured: {cfg.groq_api_key}</span>
                : <span className="key-status missing">Not set</span>
              }
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label>New Groq API Key</label>
              <input
                type="password"
                placeholder="gsk_..."
                value={groqKey}
                onChange={(e) => setGroqKey(e.target.value)}
                autoComplete="new-password"
              />
            </div>
            <a
              href="https://console.groq.com/keys"
              target="_blank"
              rel="noreferrer"
              className="get-key-link"
            >
              Get free key at console.groq.com →
            </a>
          </div>

          {/* OpenAI */}
          <div className="key-card openai-card">
            <div className="key-header">
              <span className="provider-pill openai">🤖 OpenAI</span>
              {cfg?.openai_api_key
                ? <span className="key-status configured">Configured: {cfg.openai_api_key}</span>
                : <span className="key-status missing">Not set</span>
              }
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label>New OpenAI API Key</label>
              <input
                type="password"
                placeholder="sk-proj-..."
                value={openaiKey}
                onChange={(e) => setOpenaiKey(e.target.value)}
                autoComplete="new-password"
              />
            </div>
            <a
              href="https://platform.openai.com/api-keys"
              target="_blank"
              rel="noreferrer"
              className="get-key-link"
            >
              Get key at platform.openai.com →
            </a>
          </div>

          {/* Gemini */}
          <div className="key-card gemini-card">
            <div className="key-header">
              <span className="provider-pill gemini">✨ Gemini</span>
              {cfg?.gemini_api_key
                ? <span className="key-status configured">Configured: {cfg.gemini_api_key}</span>
                : <span className="key-status missing">Not set</span>
              }
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label>New Gemini API Key</label>
              <input
                type="password"
                placeholder="AIza..."
                value={geminiKey}
                onChange={(e) => setGeminiKey(e.target.value)}
                autoComplete="new-password"
              />
            </div>
            <a
              href="https://aistudio.google.com/app/apikey"
              target="_blank"
              rel="noreferrer"
              className="get-key-link"
            >
              Get free key at aistudio.google.com →
            </a>
          </div>
        </div>
      </div>

      {/* Save Button */}
      <div className="settings-actions">
        <button
          className="btn btn-primary save-btn"
          onClick={save}
          disabled={saving}
        >
          {saving ? (
            <><span className="settings-spinner-sm" /> Saving…</>
          ) : (
            <>💾 Save Settings</>
          )}
        </button>
        <p className="save-note">Changes are written to .env and take effect on the next AI call.</p>
      </div>
    </div>
  );
}
