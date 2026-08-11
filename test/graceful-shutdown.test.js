import { test } from 'node:test';
import assert from 'node:assert/strict';
import { app, shutdown } from '../app.js';
import dbs from '../db.js';

// This test closes the shared (in-memory, per-process) database connections
// as a side effect of exercising shutdown() — it must be the only test in
// this file so it doesn't pull the database out from under other tests.
test('shutdown closes the HTTP server and the database connections', async () => {
  const server = app.listen(0);
  const { port } = server.address();

  const before = await fetch(`http://localhost:${port}/does-not-exist`);
  assert.equal(before.status, 404);

  await shutdown(server);

  await assert.rejects(() => fetch(`http://localhost:${port}/does-not-exist`));
  assert.throws(() => dbs.usersDb.prepare('SELECT 1').get());
});
