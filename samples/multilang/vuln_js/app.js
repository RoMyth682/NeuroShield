const http = require("http");
const { exec } = require("child_process");
const url = require("url");

const server = http.createServer((req, res) => {
  const q = url.parse(req.url, true).query;
  const cmd = q.cmd || "ls";
  // Vulnerable: directly executing user-controlled input
  exec(cmd, (err, stdout) => {
    res.end(err ? err.toString() : stdout);
  });
});

server.listen(3000);
