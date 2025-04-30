import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import { default as authService } from './authService.js';
import { default as jwtService } from './jwtService.js';

const { login } = authService;
const { verify } = jwtService;

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());

// Insert this middleware for protected routes
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  const payload = verify(token);

  if (!payload) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  req.user = { id: payload.sub };
  next();
}

app.post('/login', (req, res) => {
  const { id, password } = req.body;

  const result = login(id, password);
  if (!result || typeof result === 'string') {
    return res.status(401).json({ error: result || 'Invalid credentials' });
  }

  // Set token in HTTP-only cookie
  res.cookie('token', result.token, {
    httpOnly: true,
    secure: false, // Set to true if using HTTPS
    sameSite: 'strict',
    maxAge: 3600 * 1000, // 1 hour
  });

  res.json({ message: result.message });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Auth server running at http://localhost:${PORT}`);
});