import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import logRoutes from './routes/logs.js';
import usersRoutes from './routes/users.js';

const app = express();

app.use(bodyParser.json());
app.use(cookieParser());
app.use('/auth', authRoutes);
app.use('/logs', logRoutes);
app.use('/users', usersRoutes);

const PORT = 3000;

app.listen(PORT, () => {
  console.log(`Login service running at http://localhost:${PORT}`);
});