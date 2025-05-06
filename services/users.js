import Database from 'better-sqlite3';

const db = new Database('users.db');

db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created TEXT NOT NULL DEFAULT (datetime('now'))
  )
`).run();

export function getAll() {
  return db.prepare('SELECT id, email, created FROM users').all();
}

export function getById(id) {
  return db.prepare('SELECT id, email, created FROM users WHERE id = ?').get(id);
}

export function updateEmailById(id, newEmail) {
  const stmt = db.prepare('UPDATE users SET email = ? WHERE id = ?');

  try {
    const info = stmt.run(newEmail, id);

    if (info.changes === 0) {
      throw new Error(`No user found with id "${id}".`);
    }

    const updatedUser = db.prepare('SELECT id, email, created FROM users WHERE id = ?').get(id);
    return updatedUser;
  } catch (e) {
    console.error('Email update failed:', e.message);
    throw new Error('Email update failed.', { cause: e.message });
  }
}

export function deleteById(id) {
  const stmt = db.prepare('DELETE FROM users WHERE id = ?');

  try {
    const info = stmt.run(id);

    if (info.changes === 0) {
      throw new Error(`No user found with id "${id}".`);
    }

    console.log(`User with id "${id}" deleted.`);
  } catch (e) {
    console.error('Deletion failed:', e.message);
    throw new Error('User deletion failed.', { cause: e.message });
  }
}
