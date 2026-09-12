const express = require('express');
const router = express.Router();
const { pool, safeQuery } = require('../db/connection');

// VULNERABLE: raw SQL string concatenation of user input
router.get('/search', async (req, res) => {
    const q = req.query.q;
    const rows = await pool.query(`SELECT * FROM users WHERE name LIKE '%${q}%'`);
    res.json(rows);
});

// VULNERABLE: command execution from user input
router.get('/export', (req, res) => {
    const file = req.query.file;
    require('child_process').execSync(`tar -czf /tmp/export.tar.gz ${file}`);
    res.json({ ok: true });
});

// SAFE: parameterized query
router.get('/show', async (req, res) => {
    const id = req.query.id;
    const rows = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    res.json(rows);
});

// SAFE: escaped output
router.get('/preview', (req, res) => {
    const html = req.query.html;
    res.send(`<div>${String(html).replace(/[<>&"]/g, '')}</div>`);
});

module.exports = router;
