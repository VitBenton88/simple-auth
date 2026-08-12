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

const stmtGetAll = usersDb.prepare('SELECT id, email, created FROM users ORDER BY id LIMIT ? OFFSET ?');
const stmtCount = usersDb.prepare('SELECT COUNT(*) AS count FROM users');
const stmtGetById = usersDb.prepare('SELECT id, email, created FROM users WHERE id = ?');
const stmtInsert = usersDb.prepare('INSERT INTO users (email, hash, salt) VALUES (?, ?, ?) RETURNING id, email, created');
const stmtUpdateEmail = usersDb.prepare('UPDATE users SET email = ? WHERE id = ? RETURNING id, email, created');
const stmtDelete = usersDb.prepare('DELETE FROM users WHERE id = ?');
const stmtGetTokenVersion = usersDb.prepare('SELECT token_version FROM users WHERE id = ?');
const stmtBumpTokenVersion = usersDb.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ? RETURNING token_version');

export function getAll(limit = 50, offset = 0) {
  return stmtGetAll.all(limit, offset);
}

export function count() {
  return stmtCount.get().count;
}

export function getById(id) {
  return stmtGetById.get(id);
}

export async function register(email, password) {
  const normalizedEmail = email.toLowerCase();
  const { salt, hash } = await hashPassword(password);

  try {
    const user = stmtInsert.get(normalizedEmail, hash, salt);

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

  try {
    const updatedUser = stmtUpdateEmail.get(normalizedEmail, id);

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
  try {
    const info = stmtDelete.run(id);

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
  const row = stmtGetTokenVersion.get(id);
  return row ? row.token_version : null;
}

export function bumpTokenVersion(id) {
  const row = stmtBumpTokenVersion.get(id);
  return row ? row.token_version : null;
}
