// Simple Vulnerable JavaScript/Node.js App for Testing
const express = require('express');
const sqlite3 = require('sqlite3');
const { exec } = require('child_process');

const app = express();

// SQL Injection vulnerability
app.get('/user/:id', (req, res) => {
    const db = new sqlite3.Database('users.db');
    // VULNERABLE: SQL injection
    const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
    db.get(query, (err, row) => {
        res.json(row);
    });
});

// Command Injection vulnerability
app.get('/ping/:host', (req, res) => {
    // VULNERABLE: Command injection
    exec(`ping -c 1 ${req.params.host}`, (err, stdout) => {
        res.send(stdout);
    });
});

// XSS vulnerability
app.get('/comment/:text', (req, res) => {
    // VULNERABLE: XSS
    res.send(`<div>${req.params.text}</div>`);
});

// Path Traversal vulnerability
app.get('/file/:name', (req, res) => {
    const fs = require('fs');
    // VULNERABLE: Path traversal
    fs.readFile(`/var/data/${req.params.name}`, 'utf8', (err, data) => {
        res.send(data);
    });
});

app.listen(3000);
