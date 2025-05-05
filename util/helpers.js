import { randomBytes, pbkdf2Sync } from 'crypto';

function base64url(str) {
  Buffer.from(str).toString('base64url')
}

function hashPassword(password, salt = randomBytes(16).toString('hex')) {
  const hash = pbkdf2Sync(password, salt, 100_000, 64, 'sha512').toString('hex');

  return { salt, hash };
}

export default { base64url, hashPassword };