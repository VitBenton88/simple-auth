import Database from 'better-sqlite3';
import jwtServices from '../services/jwt.js';
import helpers from '../util/helpers.js';

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

function register(email, password) {
  const { salt, hash } = helpers.hashPassword(password);
  const stmt = db.prepare('INSERT INTO users (email, hash, salt) VALUES (?, ?, ?)');

  try {
    stmt.run(email, hash, salt);

    console.log(`User "${email}" registered.`);
  } catch (e) {
    console.error('Registration failed:', e.message);
    throw new Error('Registration failed.', { cause: e.message });
  }
}

function login(email, password) {
  const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
  const user = stmt.get(email);


  if (user?.id) {
    const { hash } = helpers.hashPassword(password, user.salt);

    if (hash !== user.hash) return 'Invalid password.';
  
    return {
      message: `Login successful for "${email}".`,
      token: jwtServices.createToken(user.id)
    };
  }

  return false
}

export default { login, register };