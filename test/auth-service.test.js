import { test } from 'node:test';
import assert from 'node:assert/strict';
import { register, getTokenVersion, bumpTokenVersion } from '../services/users.js';
import { login } from '../services/auth.js';

test('login returns false for an email that does not exist', () => {
  assert.equal(login('nobody@example.com', 'whatever'), false);
});

test('login returns null for a wrong password', () => {
  register('wrongpass@example.com', 'correct-horse-battery-staple');
  assert.equal(login('wrongpass@example.com', 'incorrect-password'), null);
});

test('login returns the user row (including token_version) for correct credentials', () => {
  register('rightpass@example.com', 'correct-horse-battery-staple');
  const user = login('rightpass@example.com', 'correct-horse-battery-staple');

  assert.equal(user.email, 'rightpass@example.com');
  assert.equal(user.token_version, 0);
});

test('bumpTokenVersion increments the stored token_version', () => {
  register('versioned@example.com', 'some-password');
  const user = login('versioned@example.com', 'some-password');

  assert.equal(getTokenVersion(user.id), 0);
  bumpTokenVersion(user.id);
  assert.equal(getTokenVersion(user.id), 1);
});
