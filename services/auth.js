import Database from 'better-sqlite3';
import { randomBytes, pbkdf2Sync } from 'crypto';
import jwtService from '../services/jwt.js';

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
    throw new Error(`'Registration failed:', ${e.message}`);
  }
}

// Login a user
function login(email, password) {
  const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
  const user = stmt.get(email);
  if (!user) return false;

  const { hash } = hashPassword(password, user.salt);
  if (hash !== user.hash) return 'Invalid password.';

  return {
    message: `Login successful for "${email}".`,
    token: createToken(email)
  };
}

export default { register, login };