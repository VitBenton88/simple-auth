import Database from 'better-sqlite3';

const logsDb = new Database('logs.db');
const usersDb = new Database('users.db');

logsDb.prepare(`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    success INTEGER NOT NULL, -- 0 or 1
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    message TEXT
  )
`).run();

usersDb.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created TEXT NOT NULL DEFAULT (datetime('now'))
  )
`).run();

export default { logsDb, usersDb };