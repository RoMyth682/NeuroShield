<?php
// ── A03: SQL Injection ────────────────────────
function getUser($conn, $username) {
    // Vulnerable: user input directly in query string
    $result = mysqli_query($conn, "SELECT * FROM users WHERE username='" . $username . "'");
    return mysqli_fetch_all($result);
}

// ── A03: Command Injection ────────────────────
function pingHost($host) {
    // Vulnerable: user input passed to shell command
    system("ping -c 4 " . $host);
}

// ── A03: Code Injection ───────────────────────
function calculate($expr) {
    // Vulnerable: eval with user-controlled input
    eval("$result = $expr;");
    return $result;
}

// ── A02: Hardcoded Credentials ────────────────
$db_password = "rootpassword123";
$api_key     = "hardcoded-api-key-xyz";

// ── A01: Path Traversal ───────────────────────
function readTemplate($name) {
    // Vulnerable: no path sanitization on user-supplied $name
    return file_get_contents("/var/www/templates/" . $name);
}
?>
