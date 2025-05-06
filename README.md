# Simple Auth

A minimal Express-based authentication server. For a minimal frontend UI that is compatible with this api, [refer here](https://github.com/VitBenton88/login-ui).

## Features

- Cookie handling via `cookie-parser`
- Designed for extensibility (add routes for login, logout, etc.)
- Serverless DB with SQLite!

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v23+ recommended)
- npm or yarn

### Recommendations
- [Update this.](https://github.com/VitBenton88/simple-auth/blob/d01b00ba8f3907704a466a2da818b8a6f9aa17ed/services/jwt.js#L6)
- Use middleware for protecting routes as needed. [See here.](https://github.com/VitBenton88/simple-auth/blob/9cfaf038013d9f14f1e146609e6dc4128418efef/routes/auth.js#L11)

### Installation

```bash
git clone https://github.com/yourusername/simple-auth.git
cd simple-auth
npm i