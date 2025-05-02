import Database from 'better-sqlite3';
import { randomBytes, pbkdf2Sync } from 'crypto';
import jwtService from './jwt.js';

const db = new Database('users.db');
const { createToken } = jwtService;

// Create users table
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created TEXT NOT NULL DEFAULT (datetime('now'))
  )
`).run();

// Hashing function using pbkdf2
function hashPassword(password, salt = randomBytes(16).toString('hex')) {
  const hash = pbkdf2Sync(password, salt, 100_000, 64, 'sha512').toString('hex');

  return { salt, hash };
}

// Register a user
function register(email, password) {
  const { salt, hash } = hashPassword(password);
  const stmt = db.prepare('INSERT INTO users (email, hash, salt) VALUES (?, ?, ?)');

  try {
    stmt.run(email, hash, salt);

    console.log(`User "${email}" registered.`);
  } catch (e) {
    console.error('Registration failed:', e.message);
    throw new Error('Registration failed.', { cause: e.message });
  }
}

// Login a user
function login(email, password) {
  const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
  const user = stmt.get(email);

  if (user) {
    const { hash } = hashPassword(password, user.salt);

    if (hash !== user.hash) return 'Invalid password.';
  
    return {
      message: `Login successful for "${email}".`,
      token: createToken(email)
    };
  }

  return false
}

// Get all users
function getAllUsers() {
  return db.prepare('SELECT id, email, created FROM users').all();
}

// Delete a user
function deleteUserById(id) {
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

export default { deleteUserById, getAllUsers, login, register };