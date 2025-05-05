import Database from 'better-sqlite3';

const db = new Database('logs.db');

// Create logs table
db.prepare(`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    success INTEGER NOT NULL, -- 0 or 1
    ip TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    message TEXT
  )
`).run();

function create(email, success, message) {
  const stmt = db.prepare('INSERT INTO logs (email, success, message) VALUES (?, ?, ?)');

  try {
    stmt.run(email, success, message);
  } catch (e) {
    console.error('Log creation failed: ', e.message);
  }
}

function getAll() {
  try {
    return db.prepare('SELECT * FROM logs ORDER BY timestamp DESC').all();
  } catch (e) {
    console.error('Failed to fetch logs: ', e.message);
    return [];
  }
}

export default { create, getAll };