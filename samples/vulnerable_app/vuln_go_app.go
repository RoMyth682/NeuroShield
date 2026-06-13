package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// ─── HARDCODED CREDENTIALS ────────────────────────────────────
const (
	adminPassword = "admin123"          // CWE-798: Hardcoded password
	apiSecret     = "sk-super-secret-key-do-not-share" // CWE-798
	dbConnString  = "root:password123@tcp(localhost:3306)/prod_db" // CWE-798
)

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./app.db")
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/login",    loginHandler)
	http.HandleFunc("/exec",     execHandler)
	http.HandleFunc("/file",     fileHandler)
	http.HandleFunc("/user",     userHandler)
	http.HandleFunc("/hash",     hashHandler)
	http.HandleFunc("/redirect", redirectHandler)

	fmt.Println("Server running on :8080")
	// CWE-319: Cleartext Transmission — plain HTTP, no TLS
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// ─── SQL INJECTION ────────────────────────────────────────────
// CWE-89: Improper Neutralization of SQL Commands
func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")

	// VULNERABLE: raw string interpolation into SQL — classic SQLi
	query := fmt.Sprintf(
		"SELECT * FROM users WHERE username='%s' AND password='%s'",
		username, password,
	)
	rows, err := db.Query(query) // G202: SQL query built with string concatenation
	if err != nil {
		http.Error(w, "DB error", 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "Login attempted for: %s", username)
}

// ─── COMMAND INJECTION ────────────────────────────────────────
// CWE-78: OS Command Injection
func execHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")

	// VULNERABLE: user input passed directly to shell — attacker can inject ; rm -rf /
	cmd := exec.Command("bash", "-c", "ping -c 1 "+host) // G204
	out, err := cmd.Output()
	if err != nil {
		http.Error(w, "Command failed: "+err.Error(), 500)
		return
	}
	w.Write(out)
}

// ─── PATH TRAVERSAL ──────────────────────────────────────────
// CWE-22: Improper Limitation of a Pathname
func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("name")

	// VULNERABLE: no sanitization — attacker can request ../../etc/passwd
	path := filepath.Join("/var/www/uploads", filename)
	data, err := ioutil.ReadFile(path) // G304: File path from variable
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	w.Write(data)
}

// ─── XSS / UNVALIDATED REDIRECT ──────────────────────────────
// CWE-601: Open Redirect
func redirectHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	// VULNERABLE: redirect to any attacker-controlled URL
	http.Redirect(w, r, target, http.StatusFound)
}

// ─── INSECURE DESERIALIZATION / SSRF ─────────────────────────
// CWE-918: Server-Side Request Forgery
func userHandler(w http.ResponseWriter, r *http.Request) {
	profileURL := r.URL.Query().Get("profile_url")

	// VULNERABLE: fetches any URL including internal services (169.254.169.254, localhost, etc.)
	resp, err := http.Get(profileURL) // G107: SSRF
	if err != nil {
		http.Error(w, "Fetch failed", 500)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	w.Write(body)
}

// ─── WEAK CRYPTOGRAPHY ────────────────────────────────────────
// CWE-327: Use of Broken Cryptographic Algorithm
func hashHandler(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("data")

	// VULNERABLE: MD5 is cryptographically broken — use SHA-256 or bcrypt
	hash := md5.Sum([]byte(data)) // G401: Use of weak cryptographic primitive
	fmt.Fprintf(w, "%x", hash)
}

// ─── INSECURE TEMP FILE ───────────────────────────────────────
// CWE-377: Insecure Temporary File
func writeTempData(content string) {
	// VULNERABLE: predictable temp file location — race condition / symlink attack
	tmpFile := "/tmp/app_data.txt" // G306
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	if err != nil {
		log.Printf("Failed to write temp: %v", err)
	}
}

// ─── SENSITIVE DATA EXPOSURE ──────────────────────────────────
// CWE-532: Logging of Sensitive Information
func logSensitiveData(username, password, token string) {
	// VULNERABLE: passwords and tokens written to log files
	log.Printf("User login: username=%s password=%s token=%s", username, password, token) // G104
}

// ─── IMPROPER ERROR HANDLING ──────────────────────────────────
// CWE-209: Generation of Error Message Containing Sensitive Information
func internalHandler(w http.ResponseWriter, r *http.Request) {
	_, err := os.ReadFile("/etc/app/config.yml")
	if err != nil {
		// VULNERABLE: full internal error exposed to client — leaks stack path
		http.Error(w, fmt.Sprintf("Internal error: %v — path: /etc/app/config.yml", err), 500)
	}
}

// ─── INSECURE RANDOM ─────────────────────────────────────────
// CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator
func generateToken() string {
	// VULNERABLE: math/rand is not cryptographically secure — use crypto/rand
	// Using fmt.Sprintf with non-random data as token
	return fmt.Sprintf("token-%s", strings.Repeat("x", 16)) // predictable
}
