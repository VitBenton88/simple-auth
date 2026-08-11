import { randomBytes, scrypt as scryptCallback } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);

export function base64url(str) {
  return Buffer.from(str).toString('base64url');
}

// scrypt is both memory-hard and CPU-hard (unlike PBKDF2), and the async
// form runs on libuv's threadpool instead of blocking the event loop, so a
// burst of logins/registrations can't stall the whole process the way
// pbkdf2Sync did.
export async function hashPassword(password, salt = randomBytes(16).toString('hex')) {
  const hash = (await scrypt(password, salt, 64)).toString('hex');

  return { salt, hash };
}
