import dbs from '../db.js';
import { hashPassword } from './helpers.js';

const { usersDb } = dbs;

export function getAll() {
  return usersDb.prepare('SELECT id, email, created FROM users').all();
}

export function getById(id) {
  return usersDb.prepare('SELECT id, email, created FROM users WHERE id = ?').get(id);
}

export function register(email, password) {
  const { salt, hash } = hashPassword(password);
  const stmt = usersDb.prepare('INSERT INTO users (email, hash, salt) VALUES (?, ?, ?)');

  try {
    stmt.run(email, hash, salt);

    console.log(`User "${email}" registered.`);
  } catch (e) {
    console.error('Registration failed:', e.message);
    throw new Error('Registration failed.', { cause: e.message });
  }
}

export function updateEmailById(id, newEmail) {
  const stmt = usersDb.prepare('UPDATE users SET email = ? WHERE id = ?');

  try {
    const info = stmt.run(newEmail, id);

    if (info.changes === 0) {
      throw new Error(`No user found with id "${id}".`);
    }

    const updatedUser = usersDb.prepare('SELECT id, email, created FROM users WHERE id = ?').get(id);
    return updatedUser;
  } catch (e) {
    console.error('Email update failed:', e.message);
    throw new Error('Email update failed.', { cause: e.message });
  }
}

export function deleteById(id) {
  const stmt = usersDb.prepare('DELETE FROM users WHERE id = ?');

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
