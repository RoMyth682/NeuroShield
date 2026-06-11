import { useEffect, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { User, adminApi } from "../api/client";
import { useAuth } from "../context/AuthContext";
import "./Admin.css";

interface Stats {
  total_scans: number;
  completed_scans: number;
  failed_scans: number;
  total_users: number;
}

interface ScanRow {
  id: number;
  user_id: number;
  user_email: string;
  filename: string;
  status: string;
  created_at: string;
  completed_at: string | null;
}

const STATUS_COLORS: Record<string, string> = {
  completed: "status-completed",
  failed:    "status-failed",
  pending:   "status-pending",
  sast_running: "status-running",
  cve_running:  "status-running",
  ai_running:   "status-running",
  extracting:   "status-running",
};

export default function Admin() {
  const { user: me } = useAuth();
  const navigate = useNavigate();
  const [stats, setStats]   = useState<Stats | null>(null);
  const [users, setUsers]   = useState<User[]>([]);
  const [scans, setScans]   = useState<ScanRow[]>([]);
  const [activeTab, setActiveTab] = useState<"users" | "scans">("users");
  const [roleLoading, setRoleLoading] = useState<number | null>(null);
  const [searchUser, setSearchUser] = useState("");
  const [searchScan, setSearchScan] = useState("");

  useEffect(() => {
    adminApi.stats().then((r) => setStats(r.data));
    adminApi.users().then((r) => setUsers(r.data));
    adminApi.scans().then((r) => setScans(r.data));
  }, []);

  if (me?.role !== "admin") return <Navigate to="/" replace />;

  const deleteUser = async (id: number, email: string) => {
    if (!confirm(`Delete user "${email}"? All their scans will also be removed.`)) return;
    await adminApi.deleteUser(id);
    setUsers((prev) => prev.filter((u) => u.id !== id));
  };

  const toggleRole = async (u: User) => {
    const newRole = u.role === "admin" ? "developer" : "admin";
    if (!confirm(`Change ${u.email}'s role to "${newRole}"?`)) return;
    setRoleLoading(u.id);
    try {
      const { data } = await adminApi.changeRole(u.id, newRole);
      setUsers((prev) => prev.map((x) => (x.id === u.id ? data : x)));
    } finally {
      setRoleLoading(null);
    }
  };

  const filteredUsers = users.filter(
    (u) =>
      u.email.toLowerCase().includes(searchUser.toLowerCase()) ||
      u.role.toLowerCase().includes(searchUser.toLowerCase())
  );

  const filteredScans = scans.filter(
    (s) =>
      s.user_email.toLowerCase().includes(searchScan.toLowerCase()) ||
      s.filename.toLowerCase().includes(searchScan.toLowerCase()) ||
      s.status.toLowerCase().includes(searchScan.toLowerCase())
  );

  return (
    <div className="container page admin-page">
      {/* Header */}
      <div className="admin-hero">
        <div>
          <h1 className="admin-title">🛡️ Admin Panel</h1>
          <p className="admin-subtitle">System control, user management &amp; scan monitoring</p>
        </div>
        <div className="admin-me-chip">
          <span className="admin-role-dot" />
          Logged in as <strong>{me?.email}</strong>
        </div>
      </div>

      {/* Stat cards */}
      {stats && (
        <div className="admin-stats">
          <div className="stat-card card">
            <span className="stat-icon">👥</span>
            <span className="stat-value">{stats.total_users}</span>
            <span className="stat-label">Registered Users</span>
          </div>
          <div className="stat-card card">
            <span className="stat-icon">🔍</span>
            <span className="stat-value">{stats.total_scans}</span>
            <span className="stat-label">Total Scans</span>
          </div>
          <div className="stat-card card">
            <span className="stat-icon">✅</span>
            <span className="stat-value stat-green">{stats.completed_scans}</span>
            <span className="stat-label">Completed</span>
          </div>
          <div className="stat-card card">
            <span className="stat-icon">❌</span>
            <span className="stat-value stat-red">{stats.failed_scans}</span>
            <span className="stat-label">Failed</span>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="admin-tabs">
        <button
          className={`tab-btn ${activeTab === "users" ? "active" : ""}`}
          onClick={() => setActiveTab("users")}
        >
          👥 Users ({users.length})
        </button>
        <button
          className={`tab-btn ${activeTab === "scans" ? "active" : ""}`}
          onClick={() => setActiveTab("scans")}
        >
          🔍 All Scans ({scans.length})
        </button>
      </div>

      {/* Users Tab */}
      {activeTab === "users" && (
        <div className="admin-section card">
          <div className="section-top">
            <h2>Registered Users</h2>
            <input
              className="admin-search"
              placeholder="Search by email or role…"
              value={searchUser}
              onChange={(e) => setSearchUser(e.target.value)}
            />
          </div>
          <div className="table-wrap">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>#ID</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Scans</th>
                  <th>Joined</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.map((u) => (
                  <tr key={u.id} className={u.id === me?.id ? "row-me" : ""}>
                    <td className="td-id">#{u.id}</td>
                    <td>
                      <div className="user-email-cell">
                        <div className="user-avatar">{u.email[0].toUpperCase()}</div>
                        <span>{u.email}</span>
                        {u.id === me?.id && <span className="you-badge">You</span>}
                      </div>
                    </td>
                    <td>
                      <span className={`role-badge ${u.role}`}>{u.role}</span>
                    </td>
                    <td className="td-center">{u.scan_count ?? 0}</td>
                    <td className="td-muted">
                      {u.created_at ? new Date(u.created_at).toLocaleDateString() : "—"}
                    </td>
                    <td>
                      <div className="action-btns">
                        {u.id !== me?.id && (
                          <>
                            <button
                              className={`btn btn-sm ${u.role === "admin" ? "btn-warn" : "btn-promote"}`}
                              onClick={() => toggleRole(u)}
                              disabled={roleLoading === u.id}
                            >
                              {roleLoading === u.id
                                ? "…"
                                : u.role === "admin"
                                ? "⬇ Demote"
                                : "⬆ Promote"}
                            </button>
                            <button
                              className="btn btn-sm btn-danger"
                              onClick={() => deleteUser(u.id, u.email)}
                            >
                              🗑 Delete
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
                {filteredUsers.length === 0 && (
                  <tr><td colSpan={6} className="empty-row">No users found</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Scans Tab */}
      {activeTab === "scans" && (
        <div className="admin-section card">
          <div className="section-top">
            <h2>All Scans</h2>
            <input
              className="admin-search"
              placeholder="Search by user, file or status…"
              value={searchScan}
              onChange={(e) => setSearchScan(e.target.value)}
            />
          </div>
          <div className="table-wrap">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>#ID</th>
                  <th>User</th>
                  <th>File</th>
                  <th>Status</th>
                  <th>Started</th>
                  <th>View</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((s) => (
                  <tr key={s.id}>
                    <td className="td-id">#{s.id}</td>
                    <td className="td-muted">{s.user_email}</td>
                    <td className="td-file">{s.filename}</td>
                    <td>
                      <span className={`status-pill ${STATUS_COLORS[s.status] ?? ""}`}>
                        {s.status.replace(/_/g, " ")}
                      </span>
                    </td>
                    <td className="td-muted">
                      {new Date(s.created_at).toLocaleString()}
                    </td>
                    <td>
                      {s.status === "completed" && (
                        <button
                          className="btn btn-sm btn-view"
                          onClick={() => navigate(`/results/${s.id}`)}
                        >
                          👁 View
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {filteredScans.length === 0 && (
                  <tr><td colSpan={6} className="empty-row">No scans found</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
