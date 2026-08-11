import express from 'express';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import logRoutes from './routes/logs.js';
import usersRoutes from './routes/users.js';

export const app = express();

app.use(express.json());
app.use(cookieParser());

app.use('/auth', authRoutes);
app.use('/logs', logRoutes);
app.use('/users', usersRoutes);

if (import.meta.url === `file://${process.argv[1]}`) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Login service running at http://localhost:${PORT}`);
  });
}