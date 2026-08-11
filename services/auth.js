import dbs from '../db.js';
import { hashPassword } from './helpers.js';
import { timingSafeEqual } from 'node:crypto';

const { usersDb } = dbs;

// Used to keep the "user not found" path taking roughly as long as the
// "wrong password" path, so response timing can't be used to enumerate
// registered emails.
const DUMMY_SALT = 'dummy-salt-for-timing-parity';

function safeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);

  if (bufA.length !== bufB.length) return false;

  return timingSafeEqual(bufA, bufB);
}

export async function login(email, password) {
  const stmt = usersDb.prepare('SELECT * FROM users WHERE email = ?');
  const user = stmt.get(email.toLowerCase());

  if (!user?.id) {
    await hashPassword(password, DUMMY_SALT);
    return false;
  }

  const { hash } = await hashPassword(password, user.salt);

  if (!safeEqual(hash, user.hash)) return null;

  return user;
}
