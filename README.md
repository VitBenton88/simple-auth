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
- [Update this.](https://github.com/VitBenton88/simple-auth/blob/d25825c20e71550e5ec110b8c3ca6e03bc098388/services/jwt.js#L5)
- Use middleware for protecting routes as needed. [See here.](https://github.com/VitBenton88/simple-auth/blob/d25825c20e71550e5ec110b8c3ca6e03bc098388/routes/middleware.js#L4)

### Installation

```bash
git clone https://github.com/yourusername/simple-auth.git
cd simple-auth
npm i