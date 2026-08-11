import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import { closeDb } from './db.js';
import authRoutes from './routes/auth.js';
import logRoutes from './routes/logs.js';
import usersRoutes from './routes/users.js';

// Fail fast at startup rather than on the first login/refresh request —
// services/jwt.js also checks this lazily, but that alone would let a
// misconfigured deployment pass health checks and only break once traffic
// arrives.
if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable must be set.');
}

export const app = express();

app.use(helmet());

if (process.env.CORS_ORIGIN) {
  app.use(cors({ origin: process.env.CORS_ORIGIN, credentials: true }));
} else {
  console.warn('CORS_ORIGIN is not set; cross-origin browser requests will be blocked.');
}

// express-rate-limit reads req.ip, which Express only derives from
// X-Forwarded-For when it's told to trust the proxy that set that header.
// Left unset (Express's default), any X-Forwarded-For header — which any
// reverse proxy/load balancer adds — makes express-rate-limit throw on
// every request. TRUST_PROXY takes anything Express's "trust proxy" setting
// accepts: a hop count ("1"), a keyword ("loopback"), or a specific
// IP/CIDR/comma-separated list. See https://expressjs.com/en/guide/behind-proxies.html
if (process.env.TRUST_PROXY) {
  const trustProxy = process.env.TRUST_PROXY;
  app.set('trust proxy', /^\d+$/.test(trustProxy) ? Number(trustProxy) : trustProxy);
} else {
  console.warn(
    'TRUST_PROXY is not set; if this service runs behind a reverse proxy or load balancer, ' +
      'requests will fail with ERR_ERL_UNEXPECTED_X_FORWARDED_FOR. Set TRUST_PROXY to the ' +
      'number of proxy hops in front of this service (e.g. "1"), or another value Express\'s ' +
      '"trust proxy" setting accepts, once deployed behind one.'
  );
}

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

app.use('/auth', authRoutes);
app.use('/logs', logRoutes);
app.use('/users', usersRoutes);

app.use((req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

// Final error handler: always respond with JSON and never leak internals
// (stack traces, driver error messages) to the client. Client-fault errors
// (e.g. malformed JSON bodies, which body-parser flags with a 4xx status)
// pass their status through with a generic message; anything else is
// masked as a plain 500.
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);

  if (res.headersSent) {
    return next(err);
  }

  const isClientError = err.status >= 400 && err.status < 500;
  const status = isClientError ? err.status : 500;
  const message = isClientError ? 'Invalid request.' : 'Internal server error.';

  res.status(status).json({ error: message });
});

// server.close() waits for every open connection to end before its callback
// fires — including idle keep-alive sockets, which can otherwise stall
// shutdown indefinitely. closeIdleConnections() ends those immediately;
// the timeout is a backstop that force-closes anything still active (e.g.
// a slow in-flight request) so shutdown always completes within a bounded
// time, matching the hard SIGKILL grace period most orchestrators give.
export function shutdown(server, { timeoutMs = 5000 } = {}) {
  return new Promise((resolve) => {
    const forceTimer = setTimeout(() => server.closeAllConnections(), timeoutMs);
    forceTimer.unref();

    server.close(() => {
      clearTimeout(forceTimer);
      closeDb();
      resolve();
    });

    server.closeIdleConnections();
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const PORT = process.env.PORT || 3000;
  const server = app.listen(PORT, () => {
    console.log(`Login service running at http://localhost:${PORT}`);
  });

  const handleShutdownSignal = (signal) => {
    console.log(`Received ${signal}, shutting down gracefully...`);
    shutdown(server).then(() => process.exit(0));
  };

  process.on('SIGTERM', () => handleShutdownSignal('SIGTERM'));
  process.on('SIGINT', () => handleShutdownSignal('SIGINT'));
}
