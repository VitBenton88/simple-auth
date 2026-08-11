import { test } from 'node:test';
import assert from 'node:assert/strict';
import { app } from '../app.js';

async function startServer() {
  const server = app.listen(0);
  const { port } = server.address();
  return { server, base: `http://localhost:${port}` };
}

test('malformed JSON body returns a generic 400 JSON error instead of an HTML stack trace', async () => {
  const { server, base } = await startServer();

  try {
    const res = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{not valid json',
    });

    assert.equal(res.status, 400);
    assert.match(res.headers.get('content-type') ?? '', /application\/json/);
    const body = await res.json();
    assert.equal(body.error, 'Invalid request.');
  } finally {
    server.close();
  }
});

test('unknown routes return a JSON 404 instead of the Express default HTML page', async () => {
  const { server, base } = await startServer();

  try {
    const res = await fetch(`${base}/does-not-exist`);
    assert.equal(res.status, 404);
    const body = await res.json();
    assert.equal(body.error, 'Not found.');
  } finally {
    server.close();
  }
});

test('request bodies over the size limit are rejected with 413', async () => {
  const { server, base } = await startServer();

  try {
    const oversizedPassword = 'a'.repeat(20 * 1024); // 20kb, over a 10kb body limit
    const res = await fetch(`${base}/users/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'oversized@example.com', password: oversizedPassword }),
    });

    assert.equal(res.status, 413);
  } finally {
    server.close();
  }
});

test('CORS_ORIGIN, when set, is echoed back with credentials allowed', async () => {
  const { server, base } = await startServer();

  try {
    const res = await fetch(`${base}/auth/me`, {
      headers: { Origin: process.env.CORS_ORIGIN, Authorization: 'Bearer bogus' },
    });

    assert.equal(res.headers.get('access-control-allow-origin'), process.env.CORS_ORIGIN);
    assert.equal(res.headers.get('access-control-allow-credentials'), 'true');
  } finally {
    server.close();
  }
});
