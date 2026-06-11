package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

// A03: SQL Injection via fmt.Sprintf
func getUser(db *sql.DB, username string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s'", username)
	// Vulnerable: user input embedded directly into SQL query
	db.Query(query)
}

// A03: Command Injection via exec.Command
func runCommand(userInput string) {
	// Vulnerable: user-controlled string passed to shell command
	cmd := exec.Command("bash", "-c", userInput)
	cmd.Run()
}

// A02: Hardcoded credentials
const (
	password = "admin1234"
	secret   = "jwt-secret-key"
	apiKey   = "sk-hardcoded-openai-key"
)

// A01: Path traversal
func serveFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	// Vulnerable: no path sanitization
	http.ServeFile(w, r, "/var/www/"+filename)
}

func main() {
	http.HandleFunc("/file", serveFile)
	http.ListenAndServe(":8080", nil)
}
