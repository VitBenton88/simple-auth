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

- [Node.js](https://nodejs.org/) v22+ (an even-numbered LTS line)

### Installation

```bash
git clone https://github.com/VitBenton88/simple-auth.git
cd simple-auth
npm install
```

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `JWT_SECRET` | Secret used to sign JWTs. **Required** — the server refuses to sign/verify tokens without it (no insecure fallback). | *(none — required)* |
| `ADMIN_EMAILS` | Comma-separated list of emails allowed to list all users and read the audit logs. | *(none — no admins)* |
| `CORS_ORIGIN` | Origin allowed to make credentialed cross-origin requests (e.g. the `login-ui` dev server). If unset, cross-origin browser requests are blocked. | *(none — disabled)* |
| `NODE_ENV` | Set to `production` to mark the refresh-token cookie `Secure` (requires HTTPS). | *(none)* |

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
| `POST` | `/auth/login` | No | Login, returns access token (rate limited) |
| `POST` | `/auth/logout` | No | Revokes and clears the refresh token cookie |
| `POST` | `/auth/refresh` | Cookie | Issues a new access token (rate limited) |
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
| `POST` | `/users/create` | No | Register a new user (rate limited) |
| `GET` | `/users` | Admin | List all users |
| `GET` | `/users/:id` | Owner or Admin | Get a user by ID |
| `PUT` | `/users/update/:id` | Owner | Update own email |
| `DELETE` | `/users/delete/:id` | Owner | Delete own account (204 No Content on success) |

Users can only update or delete their own account. `GET /users` and `GET /logs` require the caller's email to be listed in `ADMIN_EMAILS`. `GET /users/:id` allows either the account owner or an admin.

**POST /users/create**
```json
{ "email": "user@example.com", "password": "secret" }
```
Password must be 8-128 characters. Response: `{ "message": "...", "user": { "id": 1, "email": "...", "created": "..." } }`

**GET /users** and **GET /logs** accept `?limit=` (default 50, max 200) and `?offset=` (default 0) query params.

**PUT /users/update/:id**
```json
{ "email": "new@example.com" }
```
Response: `{ "message": "...", "user": { "id": 1, "email": "...", "created": "..." } }`

---

### Logs

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/logs` | Admin | List all logs |
| `GET` | `/logs/:id` | Admin | Get a log entry by ID |
