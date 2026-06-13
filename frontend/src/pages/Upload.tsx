import { useCallback, useState } from "react";
import { useNavigate } from "react-router-dom";
import { scanApi } from "../api/client";
import "./Upload.css";

const ALLOWED = (import.meta.env.VITE_ALLOWED_EXTENSIONS ||
  ".py,.js,.java,.zip,.ts,.jsx,.tsx,.go,.php,.rb,.cs,.c,.cpp,.h,.hpp,.rs,.kt,.swift,.dart,.sh,.bash,.ps1,.html,.htm,.css,.scss,.json,.yaml,.yml,.xml,.txt,.gradle,.erl,.ex"
).split(",");
const MAX_MB = Number(import.meta.env.VITE_MAX_UPLOAD_MB) || 10;

export default function Upload() {
  const navigate = useNavigate();
  const [dragging, setDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");

  const validate = (f: File): string | null => {
    const ext = "." + f.name.split(".").pop()?.toLowerCase();
    if (!ALLOWED.includes(ext)) {
      return `Unsupported file type. Allowed: ${ALLOWED.join(", ")}`;
    }
    if (f.size > MAX_MB * 1024 * 1024) {
      return `File exceeds ${MAX_MB} MB limit`;
    }
    return null;
  };

  const handleFile = (f: File) => {
    const err = validate(f);
    if (err) {
      setError(err);
      return;
    }
    setError("");
    setFile(f);
  };

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped) handleFile(dropped);
  }, []);

  const startScan = async () => {
    if (!file) return;
    setUploading(true);
    setError("");
    try {
      const { data } = await scanApi.upload(file);
      navigate(`/analysis/${data.session_id}`, { state: { files: data.files, filename: data.filename } });
    } catch (err: unknown) {
      const msg =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
        "Upload failed. Please try again.";
      setError(typeof msg === "string" ? msg : "Upload failed.");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="container page">
      <h1>Upload Source Code</h1>
      <p className="page-subtitle">
        Upload a ZIP archive or individual source files (.py, .js, .java). Max size: {MAX_MB} MB.
      </p>

      {error && <div className="error-banner">{error}</div>}

      <div
        className={`dropzone card ${dragging ? "dragging" : ""} ${file ? "has-file" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        <div className="dropzone-icon-wrapper">📁</div>
        {file ? (
          <>
            <p className="file-name">{file.name}</p>
            <p className="file-size">{(file.size / 1024).toFixed(1)} KB</p>
          </>
        ) : (
          <>
            <p>Drag &amp; drop your code here</p>
            <p className="dropzone-hint">or</p>
            <label className="btn btn-secondary">
              Browse Files
              <input
                type="file"
                hidden
                accept={ALLOWED.join(",")}
                onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
              />
            </label>
          </>
        )}
      </div>

      {file && (
        <div className="upload-actions">
          <button className="btn btn-secondary" onClick={() => setFile(null)}>
            Clear
          </button>
          <button className="btn btn-primary" onClick={startScan} disabled={uploading}>
            {uploading ? "Uploading..." : "Start Analysis"}
          </button>
        </div>
      )}
    </div>
  );
}
