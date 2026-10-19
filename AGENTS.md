# Working on GID

GID is a small, self-hosted task application. Keep it easy to understand, deploy, and back up.

- Use FastAPI, SQLite, and same-origin HTML/CSS/JavaScript. Avoid new services and frontend build dependencies without a concrete need.
- Enforce every task ownership, share-permission, and administration boundary on the server. An administrator has no implicit access to another user's tasks. Do not add public registration.
- Keep cookie sessions HttpOnly and use CSRF and origin checks for writes. Use scrypt for password hashing. Initial setup intentionally prints a setup code; never log account passwords, session cookies, or CSRF tokens.
- Completing a task records its completion time and hides it from active views. Preserve completed records for reports and reopening.
- Render user text safely. Keep the UI responsive, accessible, dark by default, and free of external asset dependencies.
- Keep all persistent application state under `GID_DATA_DIR` (Docker: `/data`). Keep one worker, non-root UID/GID `10001:10001`, the health endpoint, and compatibility with a read-only container filesystem.
- Keep credentials, databases, private backups, and local environment files out of Git and the Docker build context.
- For behavior changes, run `pytest -q` and add meaningful coverage for authorization, persistence, date handling, or authentication as applicable. Update the README when operation or user-facing behavior changes. Docker changes should pass the CI container smoke test.
