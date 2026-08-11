import dbs from '../db.js';

const { logsDb } = dbs;

export function create(email, success, message) {
  const stmt = logsDb.prepare('INSERT INTO logs (email, success, message) VALUES (?, ?, ?)');

  try {
    stmt.run(email, success, message);
  } catch (e) {
    console.error('Log creation failed: ', e.message);
  }
}

export function getAll(limit = 50, offset = 0) {
  try {
    return logsDb.prepare('SELECT * FROM logs ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?').all(limit, offset);
  } catch (e) {
    console.error('Failed to fetch logs: ', e.message);
    return [];
  }
}

export function getById(id) {
  return logsDb.prepare('SELECT * FROM logs WHERE id = ?').get(id);
}
