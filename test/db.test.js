import { test } from 'node:test';
import assert from 'node:assert/strict';
import dbs from '../db.js';

test('db module exposes working in-memory users and logs databases during tests', () => {
  const userCount = dbs.usersDb.prepare('SELECT COUNT(*) AS count FROM users').get();
  const logCount = dbs.logsDb.prepare('SELECT COUNT(*) AS count FROM logs').get();

  assert.equal(userCount.count, 0);
  assert.equal(logCount.count, 0);
});
