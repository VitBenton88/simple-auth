import { test } from 'node:test';
import assert from 'node:assert/strict';
import dbs from '../db.js';

test('db module exposes working in-memory users and logs databases during tests', () => {
  const userCount = dbs.usersDb.prepare('SELECT COUNT(*) AS count FROM users').get();
  const logCount = dbs.logsDb.prepare('SELECT COUNT(*) AS count FROM logs').get();

  assert.equal(userCount.count, 0);
  assert.equal(logCount.count, 0);
});

test('users table has a token_version column defaulting to 0', () => {
  const columns = dbs.usersDb.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
  assert.ok(columns.includes('token_version'), 'expected users table to have a token_version column');

  dbs.usersDb.prepare('INSERT INTO users (email, hash, salt) VALUES (?, ?, ?)')
    .run('migration-test@example.com', 'h', 's');
  const row = dbs.usersDb.prepare('SELECT token_version FROM users WHERE email = ?')
    .get('migration-test@example.com');

  assert.equal(row.token_version, 0);
});
