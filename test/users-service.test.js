import { test } from 'node:test';
import assert from 'node:assert/strict';
import { register, updateEmailById, deleteById, getAll } from '../services/users.js';
import { ConflictError, NotFoundError } from '../services/errors.js';

function uniqueEmail(label) {
  return `${label}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
}

test('register throws ConflictError for a duplicate email', async () => {
  const email = uniqueEmail('dup');
  await register(email, 'a-strong-password');

  await assert.rejects(register(email, 'another-strong-password'), ConflictError);
});

test('updateEmailById throws NotFoundError for a nonexistent id', () => {
  assert.throws(() => updateEmailById(999999, uniqueEmail('nope')), NotFoundError);
});

test('updateEmailById throws ConflictError when the new email is already taken', async () => {
  const emailA = uniqueEmail('a-conflict');
  const emailB = uniqueEmail('b-conflict');
  await register(emailA, 'a-strong-password');
  await register(emailB, 'a-strong-password');

  const userB = getAll().find((u) => u.email === emailB);

  assert.throws(() => updateEmailById(userB.id, emailA), ConflictError);
});

test('deleteById throws NotFoundError for a nonexistent id', () => {
  assert.throws(() => deleteById(999999), NotFoundError);
});

test('updating an existing email to a value that is a duplicate does not touch the row', async () => {
  const emailA = uniqueEmail('unchanged-a');
  const emailB = uniqueEmail('unchanged-b');
  await register(emailA, 'a-strong-password');
  await register(emailB, 'a-strong-password');

  const userB = getAll().find((u) => u.email === emailB);

  assert.throws(() => updateEmailById(userB.id, emailA), ConflictError);

  const stillUserB = getAll().find((u) => u.id === userB.id);
  assert.equal(stillUserB.email, emailB);
});
