import Database from 'better-sqlite3';

const db = new Database('users.db');

// Create users table
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created TEXT NOT NULL DEFAULT (datetime('now'))
  )
`).run();

// Register a user
function register(email, password) {
  const { salt, hash } = hashPassword(password);
  const stmt = db.prepare('INSERT INTO users (email, hash, salt) VALUES (?, ?, ?)');

  try {
    stmt.run(email, hash, salt);

    console.log(`User "${email}" registered.`);
  } catch (e) {
    console.error('Registration failed:', e.message);
    throw new Error('Registration failed.', { cause: e.message });
  }
}

// Login a user
function login(req, res) {
  const { email, password } = req.body;
  const ip = req.ip;

  // Dummy auth logic
  const user = { id: 123, email: 'test@example.com', password: 'secret' };

  if (email === user.email && password === user.password) {
    const token = jwt.createToken(user.id);

    logging.create(email, 1, 'Login successful');
    res.json({ token });
  } else {
    logging.create(email, 0, 'Login failed: invalid credentials');
    res.status(401).json({ error: 'Invalid credentials' });
  }
};

export default { login, register };