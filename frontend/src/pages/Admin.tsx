import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { adminApi } from "../api/client";
import { useAuth } from "../context/AuthContext";
import "./Admin.css";

interface Stats {
  total_scans: number;
  completed_scans: number;
  total_users: number;
}

interface ScanRow {
  id: number;
  user_id: number;
  filename: string;
  status: string;
  created_at: string;
  completed_at: string | null;
}

export default function Admin() {
  const { user } = useAuth();
  const [stats, setStats] = useState<Stats | null>(null);
  const [users, setUsers] = useState<{ id: number; email: string; role: string }[]>([]);
  const [scans, setScans] = useState<ScanRow[]>([]);

  useEffect(() => {
    adminApi.stats().then((r) => setStats(r.data));
    adminApi.users().then((r) => setUsers(r.data));
    adminApi.scans().then((r) => setScans(r.data));
  }, []);

  if (user?.role !== "admin") return <Navigate to="/" replace />;

  const deleteUser = async (id: number) => {
    if (!confirm("Delete this user?")) return;
    await adminApi.deleteUser(id);
    setUsers((prev) => prev.filter((u) => u.id !== id));
  };

  return (
    <div className="container page admin-page">
      <h1>Admin Dashboard</h1>
      <p className="page-subtitle">System usage statistics and user management</p>

      {stats && (
        <div className="admin-stats">
          <div className="card stat-card">
            <span className="stat-value">{stats.total_scans}</span>
            <span className="stat-label">Total Scans</span>
          </div>
          <div className="card stat-card">
            <span className="stat-value">{stats.completed_scans}</span>
            <span className="stat-label">Completed</span>
          </div>
          <div className="card stat-card">
            <span className="stat-value">{stats.total_users}</span>
            <span className="stat-label">Users</span>
          </div>
        </div>
      )}

      <section className="admin-section card">
        <h2>Registered Users</h2>
        <table className="admin-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Email</th>
              <th>Role</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.id}</td>
                <td>{u.email}</td>
                <td>{u.role}</td>
                <td>
                  {u.role !== "admin" && (
                    <button className="btn btn-secondary btn-sm" onClick={() => deleteUser(u.id)}>
                      Delete
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="admin-section card">
        <h2>Recent Scans</h2>
        <table className="admin-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>User</th>
              <th>File</th>
              <th>Status</th>
              <th>Date</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id}>
                <td>{s.id}</td>
                <td>{s.user_id}</td>
                <td>{s.filename}</td>
                <td>
                  <span className={`status-pill ${s.status}`}>{s.status}</span>
                </td>
                <td>{new Date(s.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
