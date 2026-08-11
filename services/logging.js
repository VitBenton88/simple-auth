import dbs from '../db.js';

const { logsDb } = dbs;

// Audit-log writes are best-effort: a broken logs DB shouldn't block the
// auth flow that triggered this call, so failures here are swallowed
// (logged to stderr) rather than propagated. Reads deliberately do NOT do
// this — see getAll()/getById() below — since callers need to be able to
// tell "no logs" apart from "the logs DB is broken".
export function create(email, success, message) {
  const stmt = logsDb.prepare('INSERT INTO logs (email, success, message) VALUES (?, ?, ?)');

  try {
    stmt.run(email, success, message);
  } catch (e) {
    console.error('Log creation failed: ', e.message);
  }
}

export function getAll(limit = 50, offset = 0) {
  return logsDb.prepare('SELECT * FROM logs ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?').all(limit, offset);
}

export function getById(id) {
  return logsDb.prepare('SELECT * FROM logs WHERE id = ?').get(id);
}
