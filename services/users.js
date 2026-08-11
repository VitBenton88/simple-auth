import dbs from '../db.js';
import { hashPassword } from './helpers.js';
import { ConflictError, NotFoundError } from './errors.js';

const { usersDb } = dbs;

export function getAll(limit = 50, offset = 0) {
  return usersDb.prepare('SELECT id, email, created FROM users LIMIT ? OFFSET ?').all(limit, offset);
}

export function getById(id) {
  return usersDb.prepare('SELECT id, email, created FROM users WHERE id = ?').get(id);
}

export function register(email, password) {
  const { salt, hash } = hashPassword(password);
  const stmt = usersDb.prepare('INSERT INTO users (email, hash, salt) VALUES (?, ?, ?)');

  try {
    const info = stmt.run(email, hash, salt);

    console.log(`User "${email}" registered.`);

    return usersDb.prepare('SELECT id, email, created FROM users WHERE id = ?').get(info.lastInsertRowid);
  } catch (e) {
    console.error('Registration failed:', e.message);

    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      throw new ConflictError('A user with that email already exists.');
    }

    throw new Error('Registration failed.', { cause: e.message });
  }
}

export function updateEmailById(id, newEmail) {
  const stmt = usersDb.prepare('UPDATE users SET email = ? WHERE id = ?');

  try {
    const info = stmt.run(newEmail, id);

    if (info.changes === 0) {
      throw new NotFoundError(`No user found with id "${id}".`);
    }

    const updatedUser = usersDb.prepare('SELECT id, email, created FROM users WHERE id = ?').get(id);
    return updatedUser;
  } catch (e) {
    if (e instanceof NotFoundError) throw e;

    console.error('Email update failed:', e.message);

    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      throw new ConflictError('That email is already in use.');
    }

    throw new Error('Email update failed.', { cause: e.message });
  }
}

export function deleteById(id) {
  const stmt = usersDb.prepare('DELETE FROM users WHERE id = ?');

  try {
    const info = stmt.run(id);

    if (info.changes === 0) {
      throw new NotFoundError(`No user found with id "${id}".`);
    }

    console.log(`User with id "${id}" deleted.`);
  } catch (e) {
    if (e instanceof NotFoundError) throw e;

    console.error('Deletion failed:', e.message);
    throw new Error('User deletion failed.', { cause: e.message });
  }
}

export function getTokenVersion(id) {
  const row = usersDb.prepare('SELECT token_version FROM users WHERE id = ?').get(id);
  return row ? row.token_version : null;
}

export function bumpTokenVersion(id) {
  usersDb.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ?').run(id);
}
