import { test } from 'node:test';
import assert from 'node:assert/strict';
import { app } from '../app.js';

test('responses include baseline security headers set by helmet', async () => {
  const server = app.listen(0);
  const { port } = server.address();

  try {
    const res = await fetch(`http://localhost:${port}/does-not-exist`);

    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'SAMEORIGIN');
  } finally {
    server.close();
  }
});
