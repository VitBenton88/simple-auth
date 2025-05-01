import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());

app.use(authRoutes);

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Auth server running at http://localhost:${PORT}`);
});