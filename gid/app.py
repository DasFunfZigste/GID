"""Single-container GID API, authentication, and static web application."""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict
from contextlib import asynccontextmanager, contextmanager
from datetime import date, datetime, time as local_time, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator

from . import __version__

LOGGER = logging.getLogger("uvicorn.error")
COOKIE_NAME = "gid_session"
SESSION_SECONDS = 14 * 24 * 60 * 60
USERNAME = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
DATE_FORMAT = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TIME_FORMAT = re.compile(r"^\d{2}:\d{2}$")
Priority = Literal["low", "normal", "high"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def stamp() -> str:
    return utcnow().isoformat()


def fail(status: int, detail: str) -> None:
    raise HTTPException(status_code=status, detail=detail)


def clean_text(value: str, *, trim: bool = False, multiline: bool = False) -> str:
    if any(ord(char) < 32 and not (multiline and char in "\r\n\t") for char in value):
        raise ValueError("Text contains unsupported control characters")
    return value.strip() if trim else value


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AccountFields(Input):
    username: str = Field(min_length=3, max_length=32)
    display_name: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("username")
    @classmethod
    def valid_username(cls, value: str) -> str:
        if not USERNAME.fullmatch(value):
            raise ValueError("Username must be 3-32 letters, numbers, dots, dashes, or underscores")
        return value

    @field_validator("display_name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        value = clean_text(value, trim=True)
        if not value:
            raise ValueError("Display name is required")
        return value


class Bootstrap(AccountFields):
    setup_token: str = Field(min_length=1, max_length=200)


class Login(Input):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=128)


class NewUser(AccountFields):
    is_admin: StrictBool = False


class UserUpdate(Input):
    display_name: str | None = Field(default=None, min_length=1, max_length=80)
    is_active: StrictBool | None = None
    is_admin: StrictBool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=128)

    @field_validator("display_name")
    @classmethod
    def valid_name(cls, value: str | None) -> str:
        if value is None:
            raise ValueError("Display name cannot be null")
        return AccountFields.valid_name(value)

    @field_validator("password", "is_active", "is_admin")
    @classmethod
    def not_null(cls, value):
        if value is None:
            raise ValueError("Account fields cannot be null")
        return value


class PasswordChange(Input):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class Settings(Input):
    app_name: str = Field(min_length=1, max_length=80)
    timezone: str = Field(min_length=1, max_length=100)

    @field_validator("app_name")
    @classmethod
    def valid_app_name(cls, value: str) -> str:
        return AccountFields.valid_name(value)

    @field_validator("timezone")
    @classmethod
    def valid_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("Choose a valid IANA timezone, such as America/New_York") from None
        return value


class TaskFields(Input):
    title: str = Field(min_length=1, max_length=200)
    notes: str = Field(default="", max_length=20000)
    location: str = Field(default="", max_length=300)
    due_date: str | None = None
    due_time: str | None = None
    priority: Priority = "normal"
    tags: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("title")
    @classmethod
    def valid_title(cls, value: str) -> str:
        value = clean_text(value, trim=True)
        if not value:
            raise ValueError("Task title is required")
        return value

    @field_validator("notes")
    @classmethod
    def valid_notes(cls, value: str) -> str:
        return clean_text(value, multiline=True)

    @field_validator("location")
    @classmethod
    def valid_location(cls, value: str) -> str:
        return clean_text(value, trim=True)

    @field_validator("due_date")
    @classmethod
    def valid_date(cls, value: str | None) -> str | None:
        if value is not None:
            if not DATE_FORMAT.fullmatch(value):
                raise ValueError("Due date must use YYYY-MM-DD")
            try:
                date.fromisoformat(value)
            except ValueError:
                raise ValueError("Due date must be a valid calendar date") from None
        return value

    @field_validator("due_time")
    @classmethod
    def valid_time(cls, value: str | None) -> str | None:
        if value is not None:
            if not TIME_FORMAT.fullmatch(value):
                raise ValueError("Due time must use HH:MM")
            try:
                local_time.fromisoformat(value)
            except ValueError:
                raise ValueError("Due time must be a valid 24-hour time") from None
        return value

    @field_validator("tags")
    @classmethod
    def valid_tags(cls, value: list[str]) -> list[str]:
        result = []
        for tag in value:
            tag = clean_text(tag, trim=True)
            if not 1 <= len(tag) <= 32:
                raise ValueError("Each tag must contain 1-32 characters")
            if tag.casefold() not in {item.casefold() for item in result}:
                result.append(tag)
        return result


class TaskUpdate(Input):
    title: str | None = None
    notes: str | None = None
    location: str | None = None
    due_date: str | None = None
    due_time: str | None = None
    priority: Priority | None = None
    tags: list[str] | None = None


class Share(Input):
    user_id: StrictInt = Field(gt=0)
    permission: Literal["view", "edit"]


class Shares(Input):
    shares: list[Share] = Field(max_length=500)


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"


def password_matches(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = encoded.split("$")
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Runtime:
    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir)
        self.db_path = self.data_dir / "gid.sqlite3"
        self.setup_path = self.data_dir / "setup-token.txt"
        self.lock = threading.Lock()
        self.initialized = False
        self.secure_cookie = os.environ.get("GID_COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}
        self.failures: dict[str, list[float]] = defaultdict(list)
        self.limit_lock = threading.Lock()
        self.dummy_password = ""

    def initialize(self):
        with self.lock:
            if self.initialized:
                return
            initial_zone = os.environ.get("GID_TIMEZONE", "America/New_York")
            ZoneInfo(initial_zone)
            self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.data_dir.chmod(0o700)
            with self.db() as db:
                self.db_path.chmod(0o600)
                db.execute("PRAGMA journal_mode=WAL")
                db.executescript("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                        display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
                        is_admin INTEGER NOT NULL DEFAULT 0, is_active INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS sessions (
                        token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
                        csrf_token TEXT NOT NULL, expires_at REAL NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
                    CREATE TABLE IF NOT EXISTS tasks (
                        id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id),
                        title TEXT NOT NULL, notes TEXT NOT NULL, location TEXT NOT NULL,
                        due_date TEXT, due_time TEXT, priority TEXT NOT NULL, tags TEXT NOT NULL,
                        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, completed_at TEXT
                    );
                    CREATE INDEX IF NOT EXISTS tasks_owner ON tasks(owner_id);
                    CREATE TABLE IF NOT EXISTS shares (
                        task_id INTEGER NOT NULL REFERENCES tasks(id), user_id INTEGER NOT NULL REFERENCES users(id),
                        permission TEXT NOT NULL CHECK(permission IN ('view','edit')),
                        PRIMARY KEY(task_id,user_id)
                    );
                    CREATE INDEX IF NOT EXISTS shares_user ON shares(user_id);
                    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                """)
                db.executemany("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", [("app_name", "Get It Done"), ("timezone", initial_zone)])
                needs_setup = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
            if needs_setup:
                if not self.setup_path.exists():
                    token = secrets.token_urlsafe(32)
                    try:
                        descriptor = os.open(self.setup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with os.fdopen(descriptor, "w") as file:
                            file.write(token + "\n")
                    except FileExistsError:
                        pass
                LOGGER.warning("GID first-run setup code: %s (also saved in %s)", self.setup_path.read_text().strip(), self.setup_path)
            self.dummy_password = password_hash(secrets.token_urlsafe(32))
            self.initialized = True

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.db_path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def throttle(self, keys: list[str], *, failed: bool = False, clear: bool = False):
        now = time.monotonic()
        with self.limit_lock:
            # The dictionary is bounded even when an attacker rotates usernames.
            if len(self.failures) > 5000:
                self.failures = defaultdict(list, {key: [v for v in values if v > now - 900] for key, values in self.failures.items() if any(v > now - 900 for v in values)})
                if len(self.failures) > 5000:
                    self.failures.clear()
            for index, key in enumerate(keys):
                self.failures[key] = [value for value in self.failures[key] if value > now - 900]
                if clear:
                    if index == 0:
                        self.failures.pop(key, None)
                elif failed:
                    self.failures[key].append(now)
                elif len(self.failures[key]) >= (10 if index == 0 else 60):
                    fail(429, "Too many sign-in attempts. Try again in 15 minutes.")


def public_user(row, *, admin: bool = False) -> dict:
    result = {"id": row["id"], "username": row["username"], "display_name": row["display_name"], "is_admin": bool(row["is_admin"]), "is_active": bool(row["is_active"])}
    if admin:
        result["created_at"] = row["created_at"]
    return result


def get_settings(db) -> dict:
    return dict(db.execute("SELECT key,value FROM settings").fetchall())


def get_runtime(request: Request) -> Runtime:
    return request.app.state.runtime


def get_session(request: Request) -> dict:
    runtime = get_runtime(request)
    cookie = request.cookies.get(COOKIE_NAME, "")
    if not cookie or len(cookie) > 200:
        fail(401, "Please sign in")
    with runtime.db() as db:
        row = db.execute("SELECT u.*,s.csrf_token,s.token_hash FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.is_active=1", (token_hash(cookie), time.time())).fetchone()
        if row is None:
            fail(401, "Your session has expired. Please sign in again.")
        return dict(row)


Session = Annotated[dict, Depends(get_session)]


def get_write_session(request: Request, session: Session) -> dict:
    csrf = request.headers.get("X-CSRF-Token", "")
    if not csrf or not hmac.compare_digest(csrf.encode(), session["csrf_token"].encode()):
        fail(403, "Security token is missing or invalid. Refresh the page and try again.")
    return session


WriteSession = Annotated[dict, Depends(get_write_session)]


def need_admin(session: dict):
    if not session["is_admin"]:
        fail(403, "Administrator access is required")


def create_session(db, user, response: Response, runtime: Runtime) -> dict:
    raw_token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    db.execute("DELETE FROM sessions WHERE expires_at<=?", (time.time(),))
    db.execute("INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at) VALUES(?,?,?,?)", (token_hash(raw_token), user["id"], csrf, time.time() + SESSION_SECONDS))
    response.set_cookie(COOKIE_NAME, raw_token, max_age=SESSION_SECONDS, httponly=True, secure=runtime.secure_cookie, samesite="lax", path="/")
    return {"user": public_user(user), "csrf_token": csrf, "settings": get_settings(db)}


def authorized_tasks(db, user_id: int) -> list[sqlite3.Row]:
    return db.execute("SELECT t.*,u.username AS owner_username,u.display_name AS owner_display_name FROM tasks t JOIN users u ON u.id=t.owner_id WHERE t.owner_id=? OR EXISTS(SELECT 1 FROM shares s WHERE s.task_id=t.id AND s.user_id=?)", (user_id, user_id)).fetchall()


def task_row(db, task_id: int, user_id: int, *, edit: bool = False, owner: bool = False):
    row = db.execute("SELECT t.*,u.username AS owner_username,u.display_name AS owner_display_name FROM tasks t JOIN users u ON u.id=t.owner_id WHERE t.id=?", (task_id,)).fetchone()
    if row is None:
        fail(404, "Task not found")
    if row["owner_id"] != user_id:
        share = db.execute("SELECT permission FROM shares WHERE task_id=? AND user_id=?", (task_id, user_id)).fetchone()
        if share is None:
            fail(404, "Task not found")
        if owner:
            fail(403, "Only the task owner can manage sharing")
        if edit and share["permission"] != "edit":
            fail(403, "This task is shared with view-only access")
    return row


def serialize_task(db, row, user_id: int, zone: str, *, now: datetime | None = None) -> dict:
    now = now or utcnow().astimezone(ZoneInfo(zone))
    overdue = False
    if row["due_date"] and not row["completed_at"]:
        task_date = date.fromisoformat(row["due_date"])
        if row["due_time"]:
            due = datetime.combine(task_date, local_time.fromisoformat(row["due_time"]), tzinfo=ZoneInfo(zone))
            overdue = due.astimezone(timezone.utc) < now.astimezone(timezone.utc)
        else:
            overdue = task_date < now.date()
    own = row["owner_id"] == user_id
    shares = []
    if own:
        shares = [dict(share) for share in db.execute("SELECT s.user_id,u.username,u.display_name,s.permission FROM shares s JOIN users u ON u.id=s.user_id WHERE s.task_id=? ORDER BY u.display_name COLLATE NOCASE", (row["id"],))]
    permission = "owner" if own else db.execute("SELECT permission FROM shares WHERE task_id=? AND user_id=?", (row["id"], user_id)).fetchone()[0]
    return {key: row[key] for key in ("id", "title", "notes", "location", "due_date", "due_time", "priority", "created_at", "updated_at", "completed_at")} | {"tags": json.loads(row["tags"]), "owner": {"id": row["owner_id"], "username": row["owner_username"], "display_name": row["owner_display_name"]}, "permission": permission, "is_overdue": overdue, "shares": shares}


def validate_task(data: dict) -> dict:
    try:
        fields = TaskFields.model_validate(data).model_dump()
    except Exception as error:
        if hasattr(error, "errors"):
            fail(422, "; ".join(f"{'.'.join(map(str, item['loc']))}: {item['msg']}" for item in error.errors()))
        raise
    if fields["due_time"] and not fields["due_date"]:
        fail(422, "A due time requires a due date")
    return fields


def safe_csv(value) -> str:
    text = "" if value is None else str(value)
    # Spreadsheet importers may strip leading spaces or control characters.
    if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def normalized_origin(value: str):
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return None
        return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


class RequestBodyLimit:
    """Bound JSON request memory, including bodies sent without Content-Length."""

    def __init__(self, app, max_bytes: int = 128 * 1024):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH", "DELETE"}:
            await self.app(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.max_bytes:
                response = JSONResponse(status_code=413, content={"detail": "Request is too large. Limit request bodies to 128 KiB."})
                await response(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def create_app(data_dir: str | Path | None = None) -> FastAPI:
    runtime = Runtime(data_dir or os.environ.get("GID_DATA_DIR", "/data"))

    @asynccontextmanager
    async def lifespan(application):
        runtime.initialize()
        yield

    app = FastAPI(title="Get It Done", version=__version__, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.runtime = runtime
    app.add_middleware(RequestBodyLimit)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, error):
        # Avoid returning raw input, especially passwords, from Pydantic errors.
        message = "; ".join(f"{'.'.join(map(str, item['loc'][1:]))}: {item['msg']}" for item in error.errors())
        return JSONResponse(status_code=422, content={"detail": message or "Invalid request"})

    @app.middleware("http")
    async def security(request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            expected = normalized_origin(f"{request.url.scheme}://{request.url.netloc}")
            if (origin is not None and normalized_origin(origin) != expected) or request.headers.get("sec-fetch-site") == "cross-site":
                response = JSONResponse(status_code=403, content={"detail": "Cross-origin requests are not allowed"})
            else:
                response = await call_next(request)
        else:
            response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/api/bootstrap")
    def bootstrap_status():
        with runtime.db() as db:
            return {"setup_required": not bool(db.execute("SELECT 1 FROM users LIMIT 1").fetchone()), **get_settings(db)}

    @app.post("/api/bootstrap")
    def bootstrap(body: Bootstrap, request: Request, response: Response):
        ip = request.client.host if request.client else "unknown"
        keys = [f"setup:{ip}", f"ip:{ip}"]
        runtime.throttle(keys)
        with runtime.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                fail(409, "Setup is already complete. Please sign in.")
            expected = runtime.setup_path.read_text().strip()
            if not hmac.compare_digest(body.setup_token.encode(), expected.encode()):
                runtime.throttle(keys, failed=True)
                fail(403, "The setup code is incorrect. Check the Docker logs.")
            cursor = db.execute("INSERT INTO users(username,display_name,password_hash,is_admin,created_at) VALUES(?,?,?,?,?)", (body.username, body.display_name, password_hash(body.password), 1, stamp()))
            user = db.execute("SELECT * FROM users WHERE id=?", (cursor.lastrowid,)).fetchone()
            result = create_session(db, user, response, runtime)
        runtime.setup_path.unlink(missing_ok=True)
        runtime.throttle(keys, clear=True)
        return result

    @app.post("/api/login")
    def login(body: Login, request: Request, response: Response):
        ip = request.client.host if request.client else "unknown"
        keys = [f"login:{ip}:{body.username.casefold()}", f"ip:{ip}"]
        runtime.throttle(keys)
        with runtime.db() as db:
            user = db.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (body.username,)).fetchone()
            valid = password_matches(body.password, user["password_hash"] if user else runtime.dummy_password)
            if not valid or user is None or not user["is_active"]:
                runtime.throttle(keys, failed=True)
                fail(401, "Username or password is incorrect")
            runtime.throttle(keys, clear=True)
            return create_session(db, user, response, runtime)

    @app.get("/api/me")
    def me(session: Session):
        with runtime.db() as db:
            return {"user": public_user(session), "csrf_token": session["csrf_token"], "settings": get_settings(db)}

    @app.post("/api/logout")
    def logout(response: Response, session: WriteSession):
        with runtime.db() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (session["token_hash"],))
        response.delete_cookie(COOKIE_NAME, path="/", secure=runtime.secure_cookie, httponly=True, samesite="lax")
        return {"ok": True}

    @app.post("/api/account/password")
    def change_password(body: PasswordChange, session: WriteSession):
        with runtime.db() as db:
            db.execute("BEGIN IMMEDIATE")
            user = db.execute("SELECT * FROM users WHERE id=?", (session["id"],)).fetchone()
            if not password_matches(body.current_password, user["password_hash"]):
                fail(400, "Current password is incorrect")
            db.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash(body.new_password), session["id"]))
            db.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (session["id"], session["token_hash"]))
        return {"ok": True}

    @app.get("/api/users")
    def users(session: Session):
        with runtime.db() as db:
            return [dict(row) for row in db.execute("SELECT id,username,display_name FROM users WHERE is_active=1 ORDER BY display_name COLLATE NOCASE")]

    @app.get("/api/tasks")
    def list_tasks(session: Session, view: Literal["active", "today", "upcoming", "overdue", "shared", "completed", "all"] = "active", search: str = "", priority: Priority | None = None, tag: str = ""):
        if len(search) > 300 or len(tag) > 32:
            fail(422, "Search or tag is too long")
        with runtime.db() as db:
            zone = get_settings(db)["timezone"]
            now = utcnow().astimezone(ZoneInfo(zone))
            tasks = [serialize_task(db, row, session["id"], zone, now=now) for row in authorized_tasks(db, session["id"])]
        def belongs(task, target):
            active = not bool(task["completed_at"])
            due = date.fromisoformat(task["due_date"]) if task["due_date"] else None
            return {"all": True, "active": active, "completed": not active, "today": active and due == now.date(), "upcoming": active and due is not None and now.date() < due <= now.date() + timedelta(days=7), "overdue": task["is_overdue"], "shared": active and task["permission"] != "owner"}[target]
        counts = {target: sum(belongs(task, target) for task in tasks) for target in ("active", "today", "upcoming", "overdue", "shared", "completed")}
        needle = search.casefold().strip()
        selected = [task for task in tasks if belongs(task, view) and (not priority or task["priority"] == priority) and (not tag or tag.casefold() in {item.casefold() for item in task["tags"]}) and (not needle or needle in " ".join([task["title"], task["notes"], task["location"], *task["tags"]]).casefold())]
        if view == "completed":
            selected.sort(key=lambda task: task["completed_at"], reverse=True)
        else:
            selected.sort(key=lambda task: (bool(task["completed_at"]), not task["is_overdue"], task["due_date"] or "9999-12-31", task["due_time"] or "23:59", {"high": 0, "normal": 1, "low": 2}[task["priority"]], task["created_at"]))
        return {"tasks": selected, "counts": counts, "timezone": zone}

    @app.post("/api/tasks", status_code=201)
    def create_task(body: TaskFields, session: WriteSession):
        fields = validate_task(body.model_dump())
        now = stamp()
        with runtime.db() as db:
            cursor = db.execute("INSERT INTO tasks(owner_id,title,notes,location,due_date,due_time,priority,tags,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (session["id"], fields["title"], fields["notes"], fields["location"], fields["due_date"], fields["due_time"], fields["priority"], json.dumps(fields["tags"]), now, now))
            return serialize_task(db, task_row(db, cursor.lastrowid, session["id"]), session["id"], get_settings(db)["timezone"])

    @app.get("/api/tasks/{task_id}")
    def get_task(task_id: int, session: Session):
        with runtime.db() as db:
            return serialize_task(db, task_row(db, task_id, session["id"]), session["id"], get_settings(db)["timezone"])

    @app.patch("/api/tasks/{task_id}")
    def update_task(task_id: int, body: TaskUpdate, session: WriteSession):
        with runtime.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = task_row(db, task_id, session["id"], edit=True)
            fields = {key: row[key] for key in ("title", "notes", "location", "due_date", "due_time", "priority")}
            fields["tags"] = json.loads(row["tags"])
            fields.update(body.model_dump(exclude_unset=True))
            fields = validate_task(fields)
            db.execute("UPDATE tasks SET title=?,notes=?,location=?,due_date=?,due_time=?,priority=?,tags=?,updated_at=? WHERE id=?", (fields["title"], fields["notes"], fields["location"], fields["due_date"], fields["due_time"], fields["priority"], json.dumps(fields["tags"]), stamp(), task_id))
            return serialize_task(db, task_row(db, task_id, session["id"]), session["id"], get_settings(db)["timezone"])

    def completion(task_id: int, session: dict, complete: bool):
        with runtime.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = task_row(db, task_id, session["id"], edit=True)
            if bool(row["completed_at"]) != complete:
                now = stamp()
                db.execute("UPDATE tasks SET completed_at=?,updated_at=? WHERE id=?", (now if complete else None, now, task_id))
            return serialize_task(db, task_row(db, task_id, session["id"]), session["id"], get_settings(db)["timezone"])

    @app.post("/api/tasks/{task_id}/complete")
    def complete_task(task_id: int, session: WriteSession):
        return completion(task_id, session, True)

    @app.post("/api/tasks/{task_id}/reopen")
    def reopen_task(task_id: int, session: WriteSession):
        return completion(task_id, session, False)

    @app.put("/api/tasks/{task_id}/shares")
    def update_shares(task_id: int, body: Shares, session: WriteSession):
        with runtime.db() as db:
            db.execute("BEGIN IMMEDIATE")
            task_row(db, task_id, session["id"], owner=True)
            ids = [share.user_id for share in body.shares]
            if len(ids) != len(set(ids)):
                fail(422, "Each user can appear only once in sharing permissions")
            if session["id"] in ids:
                fail(422, "A task cannot be shared with its owner")
            for user_id in ids:
                if not db.execute("SELECT 1 FROM users WHERE id=? AND is_active=1", (user_id,)).fetchone():
                    fail(422, "Sharing is only available with active platform users")
            db.execute("DELETE FROM shares WHERE task_id=?", (task_id,))
            db.executemany("INSERT INTO shares(task_id,user_id,permission) VALUES(?,?,?)", [(task_id, share.user_id, share.permission) for share in body.shares])
            db.execute("UPDATE tasks SET updated_at=? WHERE id=?", (stamp(), task_id))
            return serialize_task(db, task_row(db, task_id, session["id"]), session["id"], get_settings(db)["timezone"])

    @app.get("/api/reports/export.csv")
    def export_csv(session: Session, status: Literal["completed", "all"] = "completed"):
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer)
        columns = ("id", "title", "notes", "location", "due_date", "due_time", "priority", "tags", "owner_username", "created_at", "updated_at", "completed_at")
        writer.writerow(columns)
        with runtime.db() as db:
            for row in authorized_tasks(db, session["id"]):
                if status == "completed" and not row["completed_at"]:
                    continue
                writer.writerow([safe_csv(", ".join(json.loads(row[key])) if key == "tags" else row[key]) for key in columns])
        return Response(buffer.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="gid-tasks-{status}.csv"'})

    @app.get("/api/admin/users")
    def admin_users(session: Session):
        need_admin(session)
        with runtime.db() as db:
            return [public_user(row, admin=True) for row in db.execute("SELECT * FROM users ORDER BY created_at,id")]

    @app.post("/api/admin/users", status_code=201)
    def admin_create_user(body: NewUser, session: WriteSession):
        need_admin(session)
        with runtime.db() as db:
            try:
                cursor = db.execute("INSERT INTO users(username,display_name,password_hash,is_admin,created_at) VALUES(?,?,?,?,?)", (body.username, body.display_name, password_hash(body.password), int(body.is_admin), stamp()))
            except sqlite3.IntegrityError:
                fail(409, "That username is already in use")
            return public_user(db.execute("SELECT * FROM users WHERE id=?", (cursor.lastrowid,)).fetchone(), admin=True)

    @app.patch("/api/admin/users/{user_id}")
    def admin_update_user(user_id: int, body: UserUpdate, session: WriteSession):
        need_admin(session)
        changes = body.model_dump(exclude_unset=True)
        with runtime.db() as db:
            db.execute("BEGIN IMMEDIATE")
            user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if user is None:
                fail(404, "User not found")
            if user_id == session["id"] and (changes.get("is_active") is False or changes.get("is_admin") is False):
                fail(422, "You cannot deactivate or demote your own administrator account")
            remaining = db.execute("SELECT COUNT(*) FROM users WHERE is_active=1 AND is_admin=1 AND id<>?", (user_id,)).fetchone()[0]
            if user["is_admin"] and user["is_active"] and (changes.get("is_active") is False or changes.get("is_admin") is False) and not remaining:
                fail(422, "At least one active administrator is required")
            if "password" in changes:
                changes["password_hash"] = password_hash(changes.pop("password"))
            if changes:
                # Column names come exclusively from the validated model and internal mapping.
                db.execute(f"UPDATE users SET {','.join(key + '=?' for key in changes)} WHERE id=?", (*changes.values(), user_id))
            if changes.get("is_active") is False or "password_hash" in changes or ("is_admin" in changes and changes["is_admin"] != bool(user["is_admin"])):
                db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            return public_user(db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone(), admin=True)

    @app.get("/api/admin/settings")
    def admin_settings(session: Session):
        need_admin(session)
        with runtime.db() as db:
            return get_settings(db)

    @app.put("/api/admin/settings")
    def update_settings(body: Settings, session: WriteSession):
        need_admin(session)
        with runtime.db() as db:
            db.executemany("UPDATE settings SET value=? WHERE key=?", [(value, key) for key, value in body.model_dump().items()])
            return get_settings(db)

    static_dir = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static_dir, check_dir=False), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(static_dir / "index.html", headers={"Cache-Control": "no-cache"})

    return app


app = create_app()
