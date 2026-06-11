import axios from "axios";

const api = axios.create({
  baseURL: "/api",
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export interface User {
  id: number;
  email: string;
  role: "admin" | "developer";
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface ScanUploadResponse {
  session_id: number;
  filename: string;
  files: string[];
  message: string;
}

export interface ScanStatusResponse {
  session_id: number;
  status: string;
  message: string;
  error_message?: string;
}

export interface Finding {
  id: number;
  finding_type: "sast" | "cve";
  title: string;
  file_path: string | null;
  line_number: number | null;
  severity: "critical" | "high" | "medium" | "low";
  cwe_id: string | null;
  category: string | null;
  description: string | null;
  cvss_score: number | null;
  cve_id: string | null;
  package_name: string | null;
  package_version: string | null;
  code_snippet: string | null;
  ai_explanation: string | null;
  exploitation_scenario: string | null;
  fix_snippet: string | null;
}

export interface ScanResultsResponse {
  session_id: number;
  status: string;
  created_at: string;
  completed_at: string | null;
  severity_summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  findings: Finding[];
  ai_available: boolean;
  report_available: boolean;
  scan_warnings: string[];
}

export const authApi = {
  register: (email: string, password: string) =>
    api.post("/auth/register", { email, password }),
  login: (email: string, password: string) => {
    const form = new URLSearchParams();
    form.append("username", email);
    form.append("password", password);
    return api.post<TokenResponse>("/auth/login", form, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
  },
  me: () => api.get<User>("/auth/me"),
};

export const scanApi = {
  upload: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return api.post<ScanUploadResponse>("/scan/upload", form);
  },
  status: (sessionId: number) => api.get<ScanStatusResponse>(`/scan/${sessionId}/status`),
  results: (sessionId: number, severity?: string) =>
    api.get<ScanResultsResponse>(`/scan/${sessionId}/results`, {
      params: severity ? { severity } : {},
    }),
  downloadReport: (sessionId: number) =>
    api.get(`/scan/${sessionId}/report`, { responseType: "blob" }),
  explainFinding: (findingId: number) =>
    api.post<Finding>(`/scan/finding/${findingId}/explain`),
};

export const adminApi = {
  stats: () => api.get("/admin/stats"),
  users: () => api.get<User[]>("/admin/users"),
  deleteUser: (id: number) => api.delete(`/admin/users/${id}`),
  scans: () => api.get("/admin/scans"),
};

export default api;
