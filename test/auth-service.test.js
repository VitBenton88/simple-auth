import { test } from 'node:test';
import assert from 'node:assert/strict';
import { register, getTokenVersion, bumpTokenVersion } from '../services/users.js';
import { login } from '../services/auth.js';

test('login returns null for an email that does not exist', async () => {
  assert.equal(await login('nobody@example.com', 'whatever'), null);
});

test('login returns null for a wrong password', async () => {
  await register('wrongpass@example.com', 'correct-horse-battery-staple');
  assert.equal(await login('wrongpass@example.com', 'incorrect-password'), null);
});

test('login returns the user row (including token_version) for correct credentials', async () => {
  await register('rightpass@example.com', 'correct-horse-battery-staple');
  const user = await login('rightpass@example.com', 'correct-horse-battery-staple');

  assert.equal(user.email, 'rightpass@example.com');
  assert.equal(user.token_version, 0);
});

test('bumpTokenVersion increments the stored token_version', async () => {
  await register('versioned@example.com', 'some-password');
  const user = await login('versioned@example.com', 'some-password');

  assert.equal(getTokenVersion(user.id), 0);
  bumpTokenVersion(user.id);
  assert.equal(getTokenVersion(user.id), 1);
});
