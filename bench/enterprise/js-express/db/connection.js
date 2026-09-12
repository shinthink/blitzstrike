const { Pool } = require('pg');

// Realistic enterprise DB connection module with a safe helper.
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function safeQuery(text, params) {
    return pool.query(text, params);
}

module.exports = { pool, safeQuery };
