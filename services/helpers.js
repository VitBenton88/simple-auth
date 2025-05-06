import { randomBytes, pbkdf2Sync } from 'crypto';

export function base64url(str) {
  return Buffer.from(str).toString('base64url');
}

export function hashPassword(password, salt = randomBytes(16).toString('hex')) {
  const hash = pbkdf2Sync(password, salt, 100_000, 64, 'sha512').toString('hex');

  return { salt, hash };
}
