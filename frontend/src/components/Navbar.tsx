import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import "./Navbar.css";

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  return (
    <nav className="navbar">
      <div className="container navbar-inner">
        <Link to="/" className="navbar-brand">
          <span className="brand-icon">🛡️</span>
          NeuroShield
        </Link>
        <div className="navbar-links">
          {user ? (
            <>
              <Link to="/upload">Scan</Link>
              {user.role === "admin" && <Link to="/admin">Admin</Link>}
              <span className="user-email">{user.email}</span>
              <button
                className="btn btn-secondary"
                onClick={() => {
                  logout();
                  navigate("/");
                }}
              >
                Logout
              </button>
            </>
          ) : (
            <>
              <Link to="/login">Login</Link>
              <Link to="/register" className="btn btn-primary">
                Register
              </Link>
            </>
          )}
        </div>
      </div>
    </nav>
  );
}
