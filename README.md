# Simple Auth

A minimal Express-based authentication server using SQLite. For a compatible frontend, [see here](https://github.com/VitBenton88/login-ui).

## Features

- JWT authentication (hand-rolled, HS256)
- Short-lived access tokens + long-lived refresh tokens via httpOnly cookie
- Password hashing with PBKDF2 + random salt
- SQLite persistence via `better-sqlite3` (separate DBs for users and logs)
- Login rate limiting (10 attempts per 15 minutes per IP)

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) v23+

### Installation

```bash
git clone https://github.com/VitBenton88/simple-auth.git
cd simple-auth
npm install
```

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `JWT_SECRET` | Secret used to sign JWTs | `super-secret-key` |

Set `JWT_SECRET` to a long random string in production.

### Running

```bash
JWT_SECRET=your-secret node app.js
```

Server starts on `http://localhost:3000`.

---

## Auth Flow

1. **Register** — `POST /users/create`
2. **Login** — `POST /auth/login` returns an `accessToken` and sets a `refreshToken` httpOnly cookie
3. **Authenticated requests** — include the access token as `Authorization: Bearer <accessToken>`
4. **Refresh** — `POST /auth/refresh` uses the cookie to issue a new access token (15 min expiry)

---

## API Reference

### Auth

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/login` | No | Login, returns access token |
| `POST` | `/auth/logout` | No | Clears refresh token cookie |
| `POST` | `/auth/refresh` | Cookie | Issues a new access token |
| `GET` | `/auth/me` | Yes | Returns the authenticated user's ID |

**POST /auth/login**
```json
{ "email": "user@example.com", "password": "secret" }
```
Response: `{ "accessToken": "..." }`

---

### Users

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/users/create` | No | Register a new user |
| `GET` | `/users` | Yes | List all users |
| `GET` | `/users/:id` | Yes | Get a user by ID |
| `PUT` | `/users/update/:id` | Yes | Update own email |
| `DELETE` | `/users/delete/:id` | Yes | Delete own account |

Users can only update or delete their own account.

**POST /users/create**
```json
{ "email": "user@example.com", "password": "secret" }
```

**PUT /users/update/:id**
```json
{ "email": "new@example.com" }
```

---

### Logs

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/logs` | Yes | List all logs |
| `GET` | `/logs/:id` | Yes | Get a log entry by ID |
