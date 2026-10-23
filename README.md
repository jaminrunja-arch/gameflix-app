# GameFlix Auth Service

Spring Boot service for GameFlix that registers users, logs them in, issues a signed JWT, and uses that token to protect `GET /api/users/me`. This is the User/Auth microservice from my Module 3 architecture.

- Java 21, Spring Boot 3.5.6, Spring Security 6 (lambda `SecurityFilterChain`, no `WebSecurityConfigurerAdapter`)
- MySQL 8 through Spring Data JPA
- JWTs are signed and verified with Spring Security's built-in Nimbus `JwtEncoder` / `JwtDecoder` (HS256)

## Endpoints

| Endpoint | Behavior | Codes |
|---|---|---|
| `POST /api/auth/register` | Creates a user, hashes the password with bcrypt, returns the profile without the hash | 201, 400, 409 |
| `POST /api/auth/login` | Checks credentials, returns `{ token, tokenType, expiresIn }` | 200, 401 |
| `GET /api/users/me` | Needs `Authorization: Bearer <token>`, returns the caller's profile based on the token's `sub` claim | 200, 401 |

Example register body:

```json
{ "username": "jamin", "email": "jamin@test.com", "password": "Password123!" }
```

Example login body:

```json
{ "email": "jamin@test.com", "password": "Password123!" }
```

## How to run

### 1. Set up MySQL

Log into MySQL as root (MySQL Workbench or the `mysql` command line) and run:

```sql
CREATE DATABASE gameflix;
CREATE DATABASE gameflix_test;
CREATE USER 'gameflix_user'@'localhost' IDENTIFIED BY 'pick-a-password';
GRANT ALL PRIVILEGES ON gameflix.* TO 'gameflix_user'@'localhost';
GRANT ALL PRIVILEGES ON gameflix_test.* TO 'gameflix_user'@'localhost';
FLUSH PRIVILEGES;
```

`gameflix` is the database the app uses. `gameflix_test` is used only by the automated tests, which drop and recreate their tables every run.

### 2. Add your local config

Copy `application.properties.example` to a new file named `application-local.properties` in the project root (same folder as `pom.xml`) and fill in:

```properties
spring.datasource.username=gameflix_user
spring.datasource.password=pick-a-password
jwt.secret=<random string, at least 32 characters>
```

A good secret can be generated with `openssl rand -base64 48`. `application-local.properties` is listed in `.gitignore` so the database password and JWT secret never get committed. The same values can be passed as environment variables instead (`DB_USERNAME`, `DB_PASSWORD`, `JWT_SECRET`, and optionally `DB_URL` and `CORS_ORIGIN`).

### 3. Run it

Open the project in IntelliJ and run `GameflixAuthApplication`, or from a terminal:

```
mvn spring-boot:run
```

The service starts on `http://localhost:8080`.

### 4. Run the tests

Right click `src/test/java` in IntelliJ and choose **Run 'All Tests'**, or:

```
mvn test
```

## Schema

`schema.sql` in the repo root:

```sql
CREATE TABLE users (
  id BIGINT NOT NULL AUTO_INCREMENT,
  created_at DATETIME(6) NOT NULL,
  email VARCHAR(100) NOT NULL,
  password VARCHAR(255) NOT NULL,
  username VARCHAR(50) NOT NULL,
  PRIMARY KEY (id),
  CONSTRAINT uk_users_email UNIQUE (email),
  CONSTRAINT uk_users_username UNIQUE (username)
) ENGINE=InnoDB;
```

- `password` is `VARCHAR(255)` because it stores the hash, not the password. A bcrypt hash with the `{bcrypt}` prefix is 68 characters, so anything smaller than that would silently cut it off and every login would fail.
- Email uniqueness is enforced by the `uk_users_email` constraint in MySQL. The service does not do a "does this email exist" check first. It just inserts, and if MySQL rejects the row because of `uk_users_email`, the service returns 409. That way two registrations at the same time can't both get through.
- Emails are trimmed and lowercased before they are saved and before login lookups.

## ddl-auto choice

`spring.jpa.hibernate.ddl-auto=update` for the main app. Hibernate creates the `users` table on the first run and keeps the data between restarts, which I need so registered users are still there for the database screenshot and the JWT.io assignment. `create-drop` would wipe the table every time the app stops. The tests use a separate `gameflix_test` database with `create-drop` so test runs never touch the real data.

## Password hashing

I used **bcrypt with a work factor of 12** through Spring's `DelegatingPasswordEncoder`. Bcrypt is one of the adaptive algorithms on the OWASP Password Storage Cheat Sheet and ships with Spring Security, so it needs no extra dependency. OWASP's minimum for bcrypt is 10. 12 makes each hash four times more expensive than 10 to brute force while a single login still takes only a fraction of a second.

The delegating encoder stores the algorithm as a prefix (`{bcrypt}$2a$12$...`), so if I switch to Argon2id later, old hashes can still be verified. Bcrypt only uses the first 72 bytes of a password, so registration limits passwords to 64 characters, and the service also rejects anything over 72 bytes in UTF-8, since characters like emoji take more than one byte.

The plaintext password is never saved, never returned in a response, and never logged. `show-sql` is off, and no request bodies are logged.

## JWT design

- Signed with HS256. The secret comes from `jwt.secret` (environment variable or the untracked local file) and the app refuses to start if it is shorter than 32 bytes.
- Claims: `iss` (gameflix-auth), `sub` (the user's id), `iat`, and `exp`. Nothing else. The payload is only Base64URL encoded, not encrypted, so anyone holding the token can read it. That's why the email and username aren't in it either.
- The decoder checks the signature, the issuer, and the expiration. Spring's default timestamp validator only checks `exp` if the claim is there, so I added a validator that rejects tokens with no `exp` at all.
- **Token lifetime: 30 minutes.** That is long enough for a normal browsing session on GameFlix without logging in constantly, but short enough that a stolen token stops working quickly. There is no refresh token yet, so going much longer would mean a leaked token stays valid for a long time.

## Error handling

- 400: validation errors return `{ "error": "Invalid input", "fields": { ... } }`
- 409: `{ "error": "Email is already registered" }`
- 401 on login: always `{ "error": "Invalid email or password" }`, whether the email doesn't exist or the password is wrong. When the email doesn't exist, the service still runs a bcrypt check against a dummy hash, so that case takes about as long as a wrong password and the timing doesn't give it away.
- 401 on `/api/users/me`: missing, tampered, or expired tokens are rejected by Spring Security's resource server filter.
- CORS allows only `http://localhost:3000` (the React front end), configurable with `CORS_ORIGIN`. It is not `*`.

## Test evidence

I chose the automated option: `src/test/java/com/gameflix/auth/AuthFlowTest.java` uses `@SpringBootTest` with MockMvc against the MySQL `gameflix_test` database.

| Required case | Test |
|---|---|
| Successful registration | `registerReturns201AndNeverReturnsPassword` |
| Duplicate email rejected | `duplicateEmailReturns409` |
| Login returns a token | `loginReturnsTokenWithExpClaim` |
| Wrong password | `loginWithWrongPasswordReturns401` |
| Protected call with valid token | `meWithValidTokenReturnsProfile` |
| Protected call with missing token | `meWithoutTokenReturns401` |
| Protected call with tampered token | `meWithTamperedTokenReturns401` |

Extra tests: invalid input returns 400, unknown email gets the same message as a wrong password, the stored password is a 68 character `{bcrypt}$2a$12$` hash, expired tokens are rejected, and tokens without `exp` are rejected.

Screenshots of the passing test run and of `SELECT id, email, password FROM users;` are in the Word document submitted with this assignment.

## Module 3 design change note

My Module 3 ERD had `users(user_id, username, email, password_hash, role_id, created_at)` with a separate `roles` table. For this build I changed:

- `user_id` to `id` and `password_hash` to `password`, so the entity follows normal JPA naming and matches the query the assignment asks for.
- I dropped `role_id` and the `roles` table for now. No endpoint in this assignment checks roles, and an unused foreign key to a table with no data would just add setup steps. I'll add it back when admin-only routes (like `POST /games`) are built.
- `email` and `username` were already unique in the ERD. Now both are real named database constraints.

## AI use

I used an AI assistant (Claude) to generate the initial project structure, the security configuration, the service and controller code, the tests, and a first draft of this README.

One thing I changed: the generated CORS config allowed GET, POST, PUT, DELETE, and OPTIONS, but this service only has GET and POST endpoints. I removed PUT and DELETE so the browser only gets permission for methods the API actually uses, then reran the tests to make sure nothing broke.
