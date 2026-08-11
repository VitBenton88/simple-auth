import Database from 'better-sqlite3';

const usersDbPath = process.env.USERS_DB_PATH || 'users.db';
const logsDbPath = process.env.LOGS_DB_PATH || 'logs.db';

const logsDb = new Database(logsDbPath);
const usersDb = new Database(usersDbPath);

logsDb.prepare(`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    success INTEGER NOT NULL, -- 0 or 1
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    message TEXT
  )
`).run();

// Supports ORDER BY timestamp DESC, id DESC in services/logging.js getAll()
// without a full table scan as the logs table grows.
logsDb.prepare('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC, id DESC)').run();

usersDb.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created TEXT NOT NULL DEFAULT (datetime('now'))
  )
`).run();

// Migration: existing databases created before token-versioning was added
// won't have this column, since CREATE TABLE IF NOT EXISTS is a no-op on
// an already-existing table.
const userColumns = usersDb.prepare('PRAGMA table_info(users)').all().map((c) => c.name);

if (!userColumns.includes('token_version')) {
  usersDb.prepare('ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0').run();
}

export function closeDb() {
  usersDb.close();
  logsDb.close();
}

export default { logsDb, usersDb };