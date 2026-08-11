# Simple Auth

A minimal Express-based authentication server using SQLite. For a compatible frontend, [see here](https://github.com/VitBenton88/login-ui).

## Features

- JWT authentication (hand-rolled, HS256)
- Short-lived access tokens + long-lived refresh tokens via httpOnly cookie
- Password hashing with scrypt (memory-hard, runs off the main thread) + random salt
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
| `CORS_ORIGIN` | Comma-separated list of origins allowed to make credentialed cross-origin requests (e.g. `http://localhost:5173,https://staging.example.com`). A single origin also works. If unset, cross-origin browser requests are blocked. | *(none — disabled)* |
| `COOKIE_SECURE` | Set to `false` to allow the refresh-token cookie over plain HTTP (local development only). Secure by default. | *(none — secure)* |
| `TRUST_PROXY` | Tells Express how many reverse-proxy hops (e.g. `1`) sit in front of it, or any other value its [`trust proxy` setting](https://expressjs.com/en/guide/behind-proxies.html) accepts. **Required if this service runs behind a proxy/load balancer** — without it, rate-limited routes (`/auth/login`, `/auth/refresh`, `/users/create`) will error on every request that carries an `X-Forwarded-For` header. | *(none — assumes no proxy)* |

Set `JWT_SECRET` to a long random string in production.

**Deploying behind a proxy/load balancer?** Set `TRUST_PROXY` (see table above). This is easy to miss because the server starts up fine without it — the failure only shows up once real traffic arrives (any request carrying an `X-Forwarded-For` header, which is nearly all of them behind nginx/ALB/Cloudflare/etc.), at which point `/auth/login`, `/auth/refresh`, and `/users/create` will all return a generic `500` with no indication `TRUST_PROXY` is the cause. If you're deploying behind any reverse proxy or load balancer, set it before going live, not after debugging a broken login flow.

**Running the paired `login-ui` dev server locally over plain HTTP?** Set `COOKIE_SECURE=false`. The refresh-token cookie is secure by default (see table above), and browsers silently drop `Secure` cookies set over `http://` — refresh will look like it "just doesn't work," with no error in the response.

### Running

```bash
JWT_SECRET=your-secret node app.js
```

Server starts on `http://localhost:3000`.

### Using the services directly

The `services/*.js` modules (`login`, `register`, `updateEmailById`, etc.) are plain exported functions with no framework dependency, so they're safe to import directly into another project instead of mounting the Express router. If you do, note that they assume their input has already been shape-validated — the checks in `validation.js` (`isValidEmail`, `isValidPassword`, `isValidId`) run once, in `routes/*.js`, not inside the services themselves. Calling a service function directly with malformed input (e.g. a non-string password) will throw rather than return a clean validation error; validate first, the same way the routes do.

---

## Auth Flow

1. **Register** — `POST /users/create`
2. **Login** — `POST /auth/login` returns an `accessToken` and sets a `refreshToken` httpOnly cookie
3. **Authenticated requests** — include the access token as `Authorization: Bearer <accessToken>`
4. **Refresh** — `POST /auth/refresh` uses the cookie to issue a new access token (15 min expiry) *and rotates the refresh token itself*, re-setting the cookie. The refresh token just used stops working immediately after — see note below.

---

## API Reference

### Auth

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/login` | No | Login, returns access token (rate limited) |
| `POST` | `/auth/logout` | No | Revokes and clears the refresh token cookie |
| `POST` | `/auth/refresh` | Cookie | Issues a new access token and rotates the refresh token (rate limited) |
| `GET` | `/auth/me` | Yes | Returns the authenticated user's ID |

**POST /auth/login**
```json
{ "email": "user@example.com", "password": "secret" }
```
Response: `{ "accessToken": "..." }`

**Refresh token rotation:** every successful `/auth/refresh` call issues a brand new refresh token (re-setting the cookie) and immediately invalidates the one that was just used. This shrinks the window a stolen refresh token stays useful for, but has two consequences worth knowing before integrating:
- A client must persist the **new** `Set-Cookie` from every refresh response — reusing an old refresh token (e.g. from a stale in-memory copy) will fail with `401`.
- Revocation is per-user, not per-session: refreshing on one device/tab invalidates the refresh token on every *other* device/tab that same user is logged into. If two clients race to refresh around the same time, one will get a legitimate-looking `401 { "error": "Refresh token has been revoked" }`. A frontend integrating with this API should serialize/queue refresh calls (e.g. a single-flight mutex) rather than firing one per concurrent request.

---

### Users

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/users/create` | No | Register a new user (rate limited) |
| `GET` | `/users` | Admin | List all users |
| `GET` | `/users/:id` | Owner or Admin | Get a user by ID |
| `PUT` | `/users/update/:id` | Owner or Admin | Update a user's email |
| `DELETE` | `/users/delete/:id` | Owner or Admin | Delete a user's account (204 No Content on success) |

Users can update or delete their own account; admins can also act on any account. `GET /users` and `GET /logs` require the caller's email to be listed in `ADMIN_EMAILS`.

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
