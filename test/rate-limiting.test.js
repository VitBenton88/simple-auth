import { test } from 'node:test';
import assert from 'node:assert/strict';
import { app } from '../app.js';

function uniqueEmail(label) {
  return `${label}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
}

test('registration is rate limited after repeated attempts from the same IP', async () => {
  const server = app.listen(0);
  const { port } = server.address();
  const base = `http://localhost:${port}`;

  try {
    let lastStatus;

    for (let i = 0; i < 21; i++) {
      const res = await fetch(`${base}/users/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: uniqueEmail(`ratelimit-${i}`), password: 'a-strong-password' }),
      });
      lastStatus = res.status;
    }

    assert.equal(lastStatus, 429);
  } finally {
    server.close();
  }
});
