import Database from 'better-sqlite3';
import { createToken } from '../services/jwt.js';
import { hashPassword } from '../util/helpers.js';

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

export function login(email, password) {
  const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
  const user = stmt.get(email);


  if (user?.id) {
    const { hash } = hashPassword(password, user.salt);

    if (hash !== user.hash) return 'Invalid password.';
  
    return {
      message: `Login successful for "${email}".`,
      token: createToken(user.id)
    };
  }

  return false
}
