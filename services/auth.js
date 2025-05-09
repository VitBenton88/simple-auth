import dbs from '../db.js';
import { hashPassword } from './/helpers.js';

const { usersDb } = dbs;

export function login(email, password) {
  const stmt = usersDb.prepare('SELECT * FROM users WHERE email = ?');
  const user = stmt.get(email);

  if (user?.id) {
    const { hash } = hashPassword(password, user.salt);

    if (hash !== user.hash) return 'Invalid password.';
  
    return user;
  }

  return false
}
