import { test } from 'node:test';
import assert from 'node:assert/strict';
import { app } from '../app.js';

test('exported app starts and responds to a request', async () => {
  const server = app.listen(0);
  const { port } = server.address();

  try {
    const res = await fetch(`http://localhost:${port}/users/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});
