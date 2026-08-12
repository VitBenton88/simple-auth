import dbs from '../db.js';
import { hashPassword } from './helpers.js';
import { ConflictError, NotFoundError } from './errors.js';

const { usersDb } = dbs;

// register()/updateEmailById() assume email/password have already been
// shape-validated (see validation.js) — that happens once, in routes/*.js,
// rather than being re-checked here. Calling these directly (e.g. importing
// this service into another project without going through the HTTP routes)
// with malformed input will throw rather than return a clean validation
// error.

export function getAll(limit = 50, offset = 0) {
  return usersDb.prepare('SELECT id, email, created FROM users ORDER BY id LIMIT ? OFFSET ?').all(limit, offset);
}

export function count() {
  return usersDb.prepare('SELECT COUNT(*) AS count FROM users').get().count;
}

export function getById(id) {
  return usersDb.prepare('SELECT id, email, created FROM users WHERE id = ?').get(id);
}

export async function register(email, password) {
  const normalizedEmail = email.toLowerCase();
  const { salt, hash } = await hashPassword(password);
  const stmt = usersDb.prepare(
    'INSERT INTO users (email, hash, salt) VALUES (?, ?, ?) RETURNING id, email, created'
  );

  try {
    const user = stmt.get(normalizedEmail, hash, salt);

    console.log(`User "${normalizedEmail}" registered.`);

    return user;
  } catch (e) {
    console.error('Registration failed:', e.message);

    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      throw new ConflictError('A user with that email already exists.');
    }

    throw new Error('Registration failed.', { cause: e });
  }
}

export function updateEmailById(id, newEmail) {
  const normalizedEmail = newEmail.toLowerCase();
  const stmt = usersDb.prepare('UPDATE users SET email = ? WHERE id = ? RETURNING id, email, created');

  try {
    const updatedUser = stmt.get(normalizedEmail, id);

    if (!updatedUser) {
      throw new NotFoundError(`No user found with id "${id}".`);
    }

    return updatedUser;
  } catch (e) {
    if (e instanceof NotFoundError) throw e;

    console.error('Email update failed:', e.message);

    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      throw new ConflictError('That email is already in use.');
    }

    throw new Error('Email update failed.', { cause: e });
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
    throw new Error('User deletion failed.', { cause: e });
  }
}

export function getTokenVersion(id) {
  const row = usersDb.prepare('SELECT token_version FROM users WHERE id = ?').get(id);
  return row ? row.token_version : null;
}

export function bumpTokenVersion(id) {
  const row = usersDb
    .prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ? RETURNING token_version')
    .get(id);

  return row ? row.token_version : null;
}
