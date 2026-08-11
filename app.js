import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import { closeDb } from './db.js';
import authRoutes from './routes/auth.js';
import logRoutes from './routes/logs.js';
import usersRoutes from './routes/users.js';

export const app = express();

app.use(helmet());

if (process.env.CORS_ORIGIN) {
  app.use(cors({ origin: process.env.CORS_ORIGIN, credentials: true }));
} else {
  console.warn('CORS_ORIGIN is not set; cross-origin browser requests will be blocked.');
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

export function shutdown(server) {
  return new Promise((resolve) => {
    server.close(() => {
      closeDb();
      resolve();
    });
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
