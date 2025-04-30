const express = require('express');
const bodyParser = require('body-parser');
const { login } = require('./authService');

const app = express();
app.use(bodyParser.json());

app.post('/login', (req, res) => {
  const { id, password } = req.body;

  const result = login(id, password);
  if (!result || typeof result === 'string') {
    return res.status(401).json({ error: result || 'Invalid credentials' });
  }

  res.json({ message: result.message, token: result.token });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Auth server running at http://localhost:${PORT}`);
});