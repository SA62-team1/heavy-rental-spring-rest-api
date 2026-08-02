# Specification: Request Bearer Token REST Endpoint

| Field | Value |
|-------|--------|
| **Feature** | Request Bearer Token |
| **Status** | As-built (sole auth token endpoint) |
| **Module** | `heavy-rental-spring-rest-api` |
| **Primary path** | `GET /api/auth/getBearerToken` |
| **Method** | Specification Driven Design (SDD) |
| **Related code** | `Authentication`, `AuthService`, `JwtService`, `SecurityConfig` |
| **Environment context** | [`SPEC-project-environment.md`](./SPEC-project-environment.md) (read first) |

This document is the **single source of truth** for obtaining a Bearer access token. The only public auth endpoint is **`GET /api/auth/getBearerToken`**. It assumes the stack, database, and conventions in **SPEC-project-environment.md**. When code and these documents diverge, update them deliberately.

---

## 1. Outcomes

When this feature is correct:

1. A client can exchange valid HTTP Basic credentials for a **raw JWT access token** (`text/plain` body only).
2. The client can call protected REST endpoints by sending `Authorization: Bearer <token>`.
3. Missing or invalid credentials never return a usable token; errors use the shared JSON error shape.
4. Token lifetime, claims, and signing follow project JWT configuration.
5. Integration tests cover success and main failure paths.

---

## 2. Scope

### 2.1 In scope

- Public `GET /api/auth/getBearerToken` (HTTP Basic → plain-text JWT)
- Credential validation via Spring Security `AuthenticationManager` + JPA users
- JWT issuance (HS256) via `JwtService`
- Security `permitAll` for this path only under `/api/auth`
- Layering, configuration keys, acceptance criteria, verification

### 2.2 Out of scope (removed / not provided)

- `POST /api/auth/login` (JSON login)
- `POST /api/auth/register`
- `POST /api/auth/logout`
- `GET /api/auth/user`
- OAuth2 authorization-code / client-credentials / RFC 6749 token endpoint
- Refresh tokens, MFA, rate limiting
- User provisioning APIs (users are seeded or managed outside this endpoint)

### 2.3 Related surface

| Method | Path | Auth | Role |
|--------|------|------|------|
| `GET` | `/actuator/health`, `/info` | Public | Ops only |
| *(future protected APIs)* | `/api/**` | Bearer JWT | Consumers of the issued token |

User accounts exist in PostgreSQL (`users` table). An empty database may receive a default admin via `DefaultUserInitializer` (see environment SPEC).

---

## 3. Requirements

### Requirement 1: Request a bearer token with HTTP Basic

**User story:** As an API client, I want to exchange my username and password for a JWT so I can call protected resources with a Bearer header.

#### Acceptance criteria

1. **GIVEN** an enabled user in the database  
   **WHEN** the client sends `GET /api/auth/getBearerToken` with `Authorization: Basic base64(username:password)`  
   **THEN** the response is `200 OK`, `Content-Type` is `text/plain`, and the body is exactly the raw JWT compact string (no JSON, no `Bearer ` prefix).

2. **GIVEN** a successful response body `T`  
   **WHEN** `T` is decoded with the application `JwtDecoder`  
   **THEN** `sub` equals the authenticated username and `roles` contains that user’s `ROLE_*` authorities.

3. **GIVEN** valid credentials for user `U`  
   **WHEN** a token is issued  
   **THEN** the JWT includes `jti`, `iss`, `iat`, `exp`, `sub`, and `roles` per project JWT design.

### Requirement 2: Reject invalid or incomplete credentials

**User story:** As an API client, I want clear failures when Basic auth is missing or wrong so I do not store an invalid token.

#### Acceptance criteria

1. **GIVEN** no `Authorization` header (or non-Basic scheme)  
   **WHEN** the client calls `GET /api/auth/getBearerToken`  
   **THEN** the response is `401` with JSON `{ "error": "unauthorized", "message": "..." }` and the body is not a JWT.

2. **GIVEN** valid Basic encoding but wrong password or unknown user  
   **WHEN** the client calls `GET /api/auth/getBearerToken`  
   **THEN** the response is `401` with `{ "error": "invalid_credentials", "message": "..." }`.

3. **GIVEN** a disabled user  
   **WHEN** the client sends correct Basic credentials  
   **THEN** the response is `401` and no usable JWT is returned.

### Requirement 3: Client attaches Bearer token on protected calls

**User story:** As a client, after I receive the plain token I want to authorize later requests with the standard Bearer scheme.

#### Acceptance criteria

1. **GIVEN** raw token string `T` from getBearerToken  
   **WHEN** the client calls a protected endpoint  
   **THEN** the request includes `Authorization: Bearer T` (single space after `Bearer`).

2. **GIVEN** no Bearer token on a protected route  
   **WHEN** the client calls that route  
   **THEN** the response is `401` with `error` of `"unauthorized"`.

---

## 4. Design

### 4.1 Flow

```
Client
  │  GET /api/auth/getBearerToken
  │  Authorization: Basic ...
  ▼
Authentication.getBearerToken()
  ▼
AuthService.getBearerToken(authorizationHeader)
  │  parse Basic → username, password
  │  AuthenticationManager.authenticate(...)
  │  JwtService.generateToken(...)
  ▼
200 text/plain → jwt.getTokenValue()
```

### 4.2 API contract

#### Request

```http
GET /api/auth/getBearerToken HTTP/1.1
Authorization: Basic <base64(username:password)>
```

- No request body.
- Endpoint is **public** (`permitAll`); credentials are validated inside the service.

#### Success — `200 OK`

| Aspect | Value |
|--------|--------|
| Content-Type | `text/plain` |
| Body | Raw JWT compact serialization only |

Example body:

```text
eyJhbGciOiJIUzI1NiJ9.<payload>.<signature>
```

#### Errors — JSON

```json
{
  "error": "<code>",
  "message": "<human-readable reason>"
}
```

| HTTP | `error` | When |
|------|---------|------|
| `401` | `unauthorized` | Missing/malformed Basic header |
| `401` | `invalid_credentials` | Bad username/password (`BadCredentialsException`) |

### 4.3 JWT (issuance)

Unchanged project defaults (see environment SPEC):

| Aspect | Value |
|--------|--------|
| Algorithm | HS256 |
| Secret | `app.jwt.secret` (≥ 32 chars) |
| Issuer | `app.jwt.issuer` |
| Lifetime | `app.jwt.expirationMinutes` |

| Claim | Content |
|-------|---------|
| `jti` | Random UUID |
| `iss` | Configured issuer |
| `iat` / `exp` | Issue and expiry instants |
| `sub` | Username |
| `roles` | Authorities starting with `ROLE_` |

### 4.4 Components

| Concern | Location |
|---------|----------|
| HTTP mapping | `controller/Authentication.java` |
| Basic parse + issue | `service/AuthService.java` |
| JWT encode | `security/JwtService.java` |
| Public route | `config/SecurityConfig.java` (`GET /api/auth/getBearerToken`) |
| User load | `CustomUserDetailsService` + `User` / `UserRepository` |

### 4.5 Security notes

- Server **cannot** set the client’s next `Authorization` header; client copies the plain token into `Bearer`.
- No register/login JSON endpoints in this design.
- Logout/denylist write path is not exposed; tokens expire at `exp`. Decoder may still check `TokenDenylist` if populated later.

---

## 5. Verification

### 5.1 Acceptance checklist

- [ ] Valid Basic credentials → `200` + non-empty plain JWT  
- [ ] JWT decodes with correct `sub` and `roles`  
- [ ] Bad password → `401` `invalid_credentials`  
- [ ] Missing Basic → `401` `unauthorized`  
- [ ] Protected route without Bearer → `401`  

### 5.2 Automated coverage

| Test | Covers |
|------|--------|
| `getBearerTokenReturnsPlainTokenThatDecodes` | Success + JwtDecoder claims |
| `getBearerTokenWithBadPasswordReturns401` | Invalid credentials |
| `getBearerTokenWithoutAuthReturns401` | Missing Basic |
| `protectedEndpointWithoutTokenReturns401` | Unauthenticated protected path |

### 5.3 Manual smoke

```bash
# Obtain token (Postman: Authorization → Basic Auth)
TOKEN=$(curl -s -u 'admin:<password>' http://localhost:8080/api/auth/getBearerToken)
echo "$TOKEN"

# Use on a protected API (when available)
curl -s http://localhost:8080/<protected-path> \
  -H "Authorization: Bearer $TOKEN"
```

---

## 6. Implementation tasks (status)

- [x] Controller exposes only `GET /getBearerToken`
- [x] `AuthService` issues token from Basic credentials
- [x] `SecurityConfig` permits only this auth path
- [x] Unused login/register/logout/user DTOs and methods removed
- [x] Integration tests updated
- [x] Specs updated

---

## 7. Key decisions

| Decision | Rationale |
|----------|-----------|
| Single endpoint: getBearerToken | Simplest token issuance for tools and clients that only need the JWT string |
| HTTP Basic on GET | No body required; Postman Basic Auth maps cleanly |
| Plain text body (not JSON) | Token-only response; client pastes into Bearer field |
| No public register | User lifecycle owned by seed/DB/ops until a dedicated SDD |
| No logout endpoint | Tokens are short-lived; revoke can be added later |

---

## 8. Change control

| Version | Date | Notes |
|---------|------|--------|
| 1.0.0 | 2026-08-02 | Initial formalization including login + getBearerToken |
| 1.1.0 | 2026-08-02 | Documented getBearerToken token-only convenience |
| **2.0.0** | 2026-08-02 | **Breaking:** only `GET /api/auth/getBearerToken` remains; register/login/logout/user removed |
