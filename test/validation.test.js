import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isValidPassword } from '../validation.js';

test('isValidPassword rejects passwords shorter than 8 characters', () => {
  assert.equal(isValidPassword('short'), false);
});

test('isValidPassword accepts passwords of 8 or more characters', () => {
  assert.equal(isValidPassword('longenough'), true);
});

test('isValidPassword rejects passwords longer than 128 characters', () => {
  assert.equal(isValidPassword('a'.repeat(129)), false);
});
