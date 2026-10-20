"""Behavior and security regressions for GID's shared task boundaries."""

import csv
import io
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from gid.app import COOKIE_NAME, PASSWORD_REQUIRED, create_app, password_hash, token_hash


PASSWORD = "correct horse battery staple"


@pytest.fixture
def site(tmp_path):
    application = create_app(tmp_path)
    with TestClient(application) as client:
        yield application, client, tmp_path


def configure_admin(client):
    initial = signin(client, "admin", "admin")
    response = client.post("/api/account/password", headers=headers(initial), json={"current_password": "admin", "new_password": PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()


def headers(auth):
    return {"X-CSRF-Token": auth["csrf_token"]}


def add_user(client, admin, username, *, is_admin=False):
    response = client.post("/api/admin/users", headers=headers(admin), json={"username": username, "display_name": username.title(), "password": PASSWORD, "is_admin": is_admin})
    assert response.status_code == 201, response.text
    return response.json()


def signin(client, username, password=PASSWORD):
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()


def new_task(client, auth, **fields):
    response = client.post("/api/tasks", headers=headers(auth), json={"title": "Check the generator", **fields})
    assert response.status_code == 201, response.text
    return response.json()


def test_fresh_install_seeds_admin_and_retires_old_bootstrap(site, caplog):
    _, client, data_dir = site
    initial = client.get("/api/bootstrap")
    assert initial.json() == {"setup_required": False, "initial_password_change_required": True, "app_name": "Get It Done", "timezone": "America/New_York"}
    assert "setup_token" not in initial.text
    assert not (data_dir / "setup-token.txt").exists()
    assert client.get("/api/me").status_code == 401
    retired = client.post("/api/bootstrap", json={"setup_token": "anything", "username": "other", "display_name": "Other", "password": PASSWORD})
    assert retired.status_code in {404, 405}
    admin = signin(client, "admin", "admin")
    assert admin["user"]["is_admin"] is True
    assert admin["user"]["must_change_password"] is True
    assert admin["user"]["display_name"] == "Administrator"
    assert admin["csrf_token"]
    cookie = client.cookies.get(COOKIE_NAME)
    with sqlite3.connect(data_dir / "gid.sqlite3") as db:
        stored = db.execute("SELECT password_hash FROM users").fetchone()[0]
        stored_session = db.execute("SELECT token_hash FROM sessions").fetchone()[0]
        assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
    assert stored.startswith("scrypt$") and PASSWORD not in stored
    assert cookie not in stored_session
    assert client.get("/api/me").json()["user"]["username"] == "admin"
    assert client.get("/api/me").json()["user"]["must_change_password"] is True
    assert "setup code" not in caplog.text.lower()
    assert (data_dir.stat().st_mode & 0o777) == 0o700
    assert ((data_dir / "gid.sqlite3").stat().st_mode & 0o777) == 0o600


def test_csrf_origin_headers_and_cookie_policy(site):
    _, client, data_dir = site
    response = client.post("/api/login", json={"username": "admin", "password": "admin"})
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    initial = response.json()
    changed = client.post("/api/account/password", headers=headers(initial), json={"current_password": "admin", "new_password": PASSWORD})
    assert changed.status_code == 200
    auth = changed.json()
    assert client.post("/api/tasks", json={"title": "Blocked"}).status_code == 403
    assert client.post("/api/tasks", headers={"X-CSRF-Token": "wrong"}, json={"title": "Blocked"}).status_code == 403
    assert client.post("/api/tasks", headers=[(b"X-CSRF-Token", b"\xc3\xbc")], json={"title": "Blocked"}).status_code == 403
    assert client.post("/api/tasks", headers={**headers(auth), "Origin": "https://attacker.example"}, json={"title": "Blocked"}).status_code == 403
    assert client.post("/api/tasks", headers={**headers(auth), "Origin": "null"}, json={"title": "Blocked"}).status_code == 403
    assert client.post("/api/tasks", headers={**headers(auth), "Origin": "http://testserver"}, json={"title": "Allowed"}).status_code == 201
    assert client.post("/api/tasks", headers={**headers(auth), "Sec-Fetch-Site": "cross-site"}, json={"title": "Blocked"}).status_code == 403
    result = client.get("/api/tasks")
    assert result.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in result.headers["content-security-policy"]
    assert result.headers["cache-control"] == "no-store"


def test_admin_cannot_read_consumer_tasks_or_exports(site):
    _, client, data_dir = site
    admin = configure_admin(client)
    add_user(client, admin, "alice")
    add_user(client, admin, "bob")
    alice = signin(client, "alice")
    task = new_task(client, alice, title="Alice private task")
    assert client.get("/api/admin/users").status_code == 403
    directory = client.get("/api/users").json()
    assert set(directory[0]) == {"id", "username", "display_name"}
    bob = signin(client, "bob")
    assert client.get(f"/api/tasks/{task['id']}").status_code == 404
    assert client.patch(f"/api/tasks/{task['id']}", headers=headers(bob), json={"title": "stolen"}).status_code == 404
    admin = signin(client, "admin")
    assert client.get("/api/tasks").json()["tasks"] == []
    assert client.get(f"/api/tasks/{task['id']}").status_code == 404
    assert "Alice private task" not in client.get("/api/reports/export.csv?status=all").text
    assert client.post(f"/api/tasks/{task['id']}/complete", headers=headers(admin)).status_code == 404


def test_share_view_edit_downgrade_revoke_and_owner_controls(site):
    _, client, data_dir = site
    admin = configure_admin(client)
    alice_user = add_user(client, admin, "alice")
    bob_user = add_user(client, admin, "bob")
    alice = signin(client, "alice")
    task = new_task(client, alice)
    task_url = f"/api/tasks/{task['id']}"
    share_url = task_url + "/shares"
    shared = client.put(share_url, headers=headers(alice), json={"shares": [{"user_id": bob_user["id"], "permission": "view"}]})
    assert shared.status_code == 200
    assert shared.json()["shares"][0]["permission"] == "view"
    bob = signin(client, "bob")
    view = client.get(task_url).json()
    assert view["permission"] == "view" and view["shares"] == []
    assert client.get("/api/tasks?view=shared").json()["counts"]["shared"] == 1
    assert client.patch(task_url, headers=headers(bob), json={"title": "Blocked"}).status_code == 403
    assert client.post(task_url + "/complete", headers=headers(bob)).status_code == 403
    assert client.post(task_url + "/reopen", headers=headers(bob)).status_code == 403
    assert client.put(share_url, headers=headers(bob), json={"shares": []}).status_code == 403
    alice = signin(client, "alice")
    assert client.put(share_url, headers=headers(alice), json={"shares": [{"user_id": alice_user["id"], "permission": "edit"}]}).status_code == 422
    assert client.put(share_url, headers=headers(alice), json={"shares": [{"user_id": 999999, "permission": "edit"}]}).status_code == 422
    assert client.put(share_url, headers=headers(alice), json={"shares": [{"user_id": bob_user["id"], "permission": "edit"}]}).status_code == 200
    bob = signin(client, "bob")
    edited = client.patch(task_url, headers=headers(bob), json={"notes": "Bob checked it"})
    assert edited.status_code == 200 and edited.json()["notes"] == "Bob checked it"
    assert client.post(task_url + "/complete", headers=headers(bob)).json()["completed_at"]
    assert client.post(task_url + "/reopen", headers=headers(bob)).json()["completed_at"] is None
    alice = signin(client, "alice")
    assert client.put(share_url, headers=headers(alice), json={"shares": [{"user_id": bob_user["id"], "permission": "view"}]}).status_code == 200
    bob = signin(client, "bob")
    assert client.patch(task_url, headers=headers(bob), json={"notes": "Blocked now"}).status_code == 403
    alice = signin(client, "alice")
    assert client.put(share_url, headers=headers(alice), json={"shares": []}).status_code == 200
    bob = signin(client, "bob")
    assert client.get(task_url).status_code == 404
    assert client.get("/api/tasks?view=all").json()["tasks"] == []
    assert "Check the generator" not in client.get("/api/reports/export.csv?status=all").text


def test_completed_tasks_retained_across_restart_and_reopened(site):
    _, client, data_dir = site
    admin = configure_admin(client)
    task = new_task(client, admin)
    url = f"/api/tasks/{task['id']}"
    result = client.post(url + "/complete", headers=headers(admin)).json()
    completed_at = result["completed_at"]
    assert completed_at and not result["is_overdue"]
    assert client.post(url + "/complete", headers=headers(admin)).json()["completed_at"] == completed_at
    assert client.get("/api/tasks").json()["tasks"] == []
    assert client.get("/api/tasks?view=completed").json()["tasks"][0]["id"] == task["id"]
    with TestClient(create_app(data_dir)) as restarted:
        logged = signin(restarted, "admin")
        retained = restarted.get(url).json()
        assert retained["completed_at"] == completed_at
        assert retained["created_at"] == task["created_at"]
        assert restarted.post(url + "/reopen", headers=headers(logged)).json()["completed_at"] is None
        assert restarted.get("/api/tasks").json()["counts"]["active"] == 1


def test_overdue_local_dates_times_filters_and_counts(site, monkeypatch):
    import gid.app as backend

    # 10:00 in New York; date-only today is not overdue while 09:59 is.
    now = datetime(2026, 10, 19, 14, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(backend, "utcnow", lambda: now)
    _, client, data_dir = site
    admin = configure_admin(client)
    yesterday = new_task(client, admin, title="Past date", due_date="2026-10-18", priority="high", tags=["Home"])
    today = new_task(client, admin, title="Today anytime", due_date="2026-10-19")
    past_time = new_task(client, admin, title="Earlier today", due_date="2026-10-19", due_time="09:59")
    future_time = new_task(client, admin, title="Later today", due_date="2026-10-19", due_time="10:01")
    soon = new_task(client, admin, title="Soon", due_date="2026-10-26")
    new_task(client, admin, title="Further away", due_date="2026-10-27")
    new_task(client, admin, title="Undated")
    tasks = client.get("/api/tasks").json()
    assert tasks["counts"] == {"active": 7, "today": 3, "upcoming": 1, "overdue": 2, "shared": 0, "completed": 0}
    assert {item["id"] for item in client.get("/api/tasks?view=overdue").json()["tasks"]} == {yesterday["id"], past_time["id"]}
    assert not client.get(f"/api/tasks/{today['id']}").json()["is_overdue"]
    assert not client.get(f"/api/tasks/{future_time['id']}").json()["is_overdue"]
    assert client.get("/api/tasks?view=upcoming").json()["tasks"][0]["id"] == soon["id"]
    filtered = client.get("/api/tasks?search=past&priority=high&tag=home").json()
    assert len(filtered["tasks"]) == 1 and filtered["counts"] == tasks["counts"]
    # Changing timezone recalculates due times rather than changing stored dates.
    assert client.put("/api/admin/settings", headers=headers(admin), json={"app_name": "Our tasks", "timezone": "America/Los_Angeles"}).status_code == 200
    assert client.get(f"/api/tasks/{past_time['id']}").json()["is_overdue"] is False
    assert client.get("/api/tasks").json()["timezone"] == "America/Los_Angeles"


def test_csv_formula_escape_and_authorized_shared_export(site):
    _, client, data_dir = site
    admin = configure_admin(client)
    user = add_user(client, admin, "reader")
    task = new_task(client, admin, title="=HYPERLINK(\"evil\")", notes="  +cmd", location="@formula", tags=["-tag"])
    private = new_task(client, admin, title="Private task")
    assert client.put(f"/api/tasks/{task['id']}/shares", headers=headers(admin), json={"shares": [{"user_id": user["id"], "permission": "view"}]}).status_code == 200
    signin(client, "reader")
    response = client.get("/api/reports/export.csv?status=all")
    assert response.status_code == 200 and "attachment" in response.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert len(rows) == 1
    assert rows[0]["title"].startswith("'=")
    assert rows[0]["notes"].startswith("'  +")
    assert rows[0]["location"] == "'@formula"
    assert rows[0]["tags"] == "'-tag"
    assert rows[0]["owner_username"] == "admin"
    assert "Private task" not in response.text
    assert list(csv.DictReader(io.StringIO(client.get("/api/reports/export.csv").text))) == []
    assert client.get("/api/reports/export.csv?status=invalid").status_code == 422


def test_disable_password_reset_and_admin_boundaries(site):
    application, client, data_dir = site
    admin = configure_admin(client)
    user = add_user(client, admin, "consumer")
    consumer = signin(client, "consumer")
    old_cookie = client.cookies.get(COOKIE_NAME)
    admin = signin(client, "admin")
    own_id = admin["user"]["id"]
    assert client.patch(f"/api/admin/users/{own_id}", headers=headers(admin), json={"display_name": "Updated Admin", "is_admin": True, "is_active": True}).status_code == 200
    assert client.get("/api/me").status_code == 200
    assert client.patch(f"/api/admin/users/{own_id}", headers=headers(admin), json={"is_active": False}).status_code == 422
    assert client.patch(f"/api/admin/users/{own_id}", headers=headers(admin), json={"is_admin": False}).status_code == 422
    assert client.patch(f"/api/admin/users/{user['id']}", headers=headers(admin), json={"is_active": False}).status_code == 200
    with TestClient(application) as disabled:
        disabled.cookies.set(COOKIE_NAME, old_cookie)
        assert disabled.get("/api/me").status_code == 401
        assert disabled.post("/api/login", json={"username": "consumer", "password": PASSWORD}).status_code == 401
    assert user["id"] not in {item["id"] for item in client.get("/api/users").json()}
    assert client.patch(f"/api/admin/users/{user['id']}", headers=headers(admin), json={"is_active": True}).status_code == 200
    with TestClient(application) as existing:
        signin(existing, "consumer")
        assert client.patch(f"/api/admin/users/{user['id']}", headers=headers(admin), json={"password": "new consumer password"}).status_code == 200
        assert existing.get("/api/me").status_code == 401
        assert existing.post("/api/login", json={"username": "consumer", "password": PASSWORD}).status_code == 401
        assert existing.post("/api/login", json={"username": "consumer", "password": "new consumer password"}).status_code == 200


def test_personal_password_change_revokes_other_sessions_and_logout(site):
    application, client, data_dir = site
    admin = configure_admin(client)
    with TestClient(application) as other:
        signin(other, "admin")
        assert client.post("/api/account/password", headers=headers(admin), json={"current_password": "wrong", "new_password": "replacement strong password"}).status_code == 400
        old_csrf = admin["csrf_token"]
        old_cookie = client.cookies.get(COOKIE_NAME)
        changed = client.post("/api/account/password", headers=headers(admin), json={"current_password": PASSWORD, "new_password": "replacement strong password"})
        assert changed.status_code == 200
        admin = changed.json()
        assert admin["ok"] is True and admin["user"]["must_change_password"] is False
        assert admin["csrf_token"] != old_csrf and client.cookies.get(COOKIE_NAME) != old_cookie
        assert other.get("/api/me").status_code == 401
        assert client.get("/api/me").status_code == 200
        assert client.post("/api/tasks", headers={"X-CSRF-Token": old_csrf}, json={"title": "Old security token"}).status_code == 403
        new_task(client, admin, title="Rotated session works")
        assert other.post("/api/login", json={"username": "admin", "password": PASSWORD}).status_code == 401
        signin(other, "admin", "replacement strong password")
    assert client.post("/api/logout", headers=headers(admin)).status_code == 200
    assert client.get("/api/me").status_code == 401


def test_default_admin_cannot_bypass_required_change_through_any_protected_api(site):
    _, client, _ = site
    initial = signin(client, "admin", "admin")
    assert client.get("/api/me").json()["user"]["must_change_password"] is True
    operations = [
        ("GET", "/api/users", None),
        ("GET", "/api/tasks", None),
        ("GET", "/api/tasks?view=completed", None),
        ("GET", "/api/tasks/1", None),
        ("POST", "/api/tasks", {"title": "Must be blocked"}),
        ("PATCH", "/api/tasks/1", {"title": "Must be blocked"}),
        ("POST", "/api/tasks/1/complete", None),
        ("POST", "/api/tasks/1/reopen", None),
        ("PUT", "/api/tasks/1/shares", {"shares": []}),
        ("GET", "/api/reports/export.csv?status=all", None),
        ("GET", "/api/reports/export.csv?status=completed", None),
        ("GET", "/api/admin/users", None),
        ("POST", "/api/admin/users", {"username": "bypass", "display_name": "Bypass", "password": PASSWORD}),
        ("PATCH", "/api/admin/users/1", {"password": PASSWORD}),
        ("GET", "/api/admin/settings", None),
        ("PUT", "/api/admin/settings", {"app_name": "Bypass", "timezone": "UTC"}),
    ]
    for method, path, body in operations:
        response = client.request(method, path, headers=headers(initial), json=body)
        assert response.status_code == 403, (method, path, response.text)
        assert response.json() == {"detail": PASSWORD_REQUIRED}
    assert client.get("/api/health").json() == {"status": "ok", "version": "0.1.1"}


def test_required_change_rejects_weak_wrong_and_unprotected_password_requests(site):
    _, client, _ = site
    initial = signin(client, "admin", "admin")
    cookie = client.cookies.get(COOKIE_NAME)
    good_body = {"current_password": "admin", "new_password": PASSWORD}
    assert client.post("/api/account/password", json=good_body).status_code == 403
    assert client.post("/api/account/password", headers={"X-CSRF-Token": "wrong"}, json=good_body).status_code == 403
    assert client.post("/api/account/password", headers={**headers(initial), "Origin": "https://attacker.example"}, json=good_body).status_code == 403
    for weak in ("admin", "short", "x" * 129):
        assert client.post("/api/account/password", headers=headers(initial), json={"current_password": "admin", "new_password": weak}).status_code == 422
    assert client.post("/api/account/password", headers=headers(initial), json={"current_password": "wrong", "new_password": PASSWORD}).status_code == 400
    assert client.cookies.get(COOKIE_NAME) == cookie
    assert client.get("/api/me").json()["user"]["must_change_password"] is True
    assert client.get("/api/bootstrap").json()["initial_password_change_required"] is True
    assert client.get("/api/tasks").json() == {"detail": PASSWORD_REQUIRED}
    assert client.post("/api/logout").status_code == 403
    assert client.post("/api/logout", headers=headers(initial)).status_code == 200
    assert client.get("/api/me").status_code == 401
    assert signin(client, "admin", "admin")["user"]["must_change_password"] is True


def test_required_change_rotates_session_and_revokes_all_other_default_logins(site):
    application, client, data_dir = site
    first = signin(client, "admin", "admin")
    first_cookie = client.cookies.get(COOKIE_NAME)
    with TestClient(application) as second, TestClient(application) as third:
        second_auth = signin(second, "admin", "admin")
        third_auth = signin(third, "admin", "admin")
        assert second_auth["user"]["must_change_password"] and third_auth["user"]["must_change_password"]
        changed = client.post("/api/account/password", headers=headers(first), json={"current_password": "admin", "new_password": PASSWORD})
        assert changed.status_code == 200
        current = changed.json()
        assert set(current) == {"ok", "user", "csrf_token", "settings"}
        assert current["ok"] and current["user"]["must_change_password"] is False
        assert current["csrf_token"] != first["csrf_token"]
        assert client.cookies.get(COOKIE_NAME) != first_cookie
        assert second.get("/api/me").status_code == 401
        assert third.post("/api/account/password", headers=headers(third_auth), json={"current_password": "admin", "new_password": "another strong password"}).status_code == 401
        with TestClient(application) as stale:
            stale.cookies.set(COOKIE_NAME, first_cookie)
            assert stale.get("/api/me").status_code == 401
            assert stale.post("/api/tasks", headers=headers(first), json={"title": "Revoked session"}).status_code == 401
        assert client.post("/api/tasks", headers=headers(first), json={"title": "Old CSRF"}).status_code == 403
        task = new_task(client, current, title="After mandatory password change")
        assert client.get("/api/bootstrap").json()["initial_password_change_required"] is False
        assert second.post("/api/login", json={"username": "admin", "password": "admin"}).status_code == 401
        assert signin(second, "admin")["user"]["must_change_password"] is False
    with TestClient(create_app(data_dir)) as restarted:
        assert restarted.get("/api/bootstrap").json()["initial_password_change_required"] is False
        assert restarted.post("/api/login", json={"username": "admin", "password": "admin"}).status_code == 401
        assert signin(restarted, "admin")["user"]["must_change_password"] is False
        assert restarted.get(f"/api/tasks/{task['id']}").json()["title"] == "After mandatory password change"


def test_pending_default_change_and_existing_session_persist_across_restart(site):
    _, client, data_dir = site
    pending = signin(client, "admin", "admin")
    cookie = client.cookies.get(COOKIE_NAME)
    with sqlite3.connect(data_dir / "gid.sqlite3") as db:
        before = db.execute("SELECT id,password_hash,must_change_password FROM users").fetchall()
    with TestClient(create_app(data_dir)) as restarted:
        restarted.cookies.set(COOKIE_NAME, cookie)
        me = restarted.get("/api/me")
        assert me.status_code == 200 and me.json()["user"]["must_change_password"] is True
        assert me.json()["csrf_token"] == pending["csrf_token"]
        assert restarted.get("/api/tasks").json() == {"detail": PASSWORD_REQUIRED}
        assert restarted.get("/api/bootstrap").json()["initial_password_change_required"] is True
        with sqlite3.connect(data_dir / "gid.sqlite3") as db:
            assert db.execute("SELECT id,password_hash,must_change_password FROM users").fetchall() == before


# The actual v0.1.0 schema, deliberately without must_change_password. These
# fixtures test an upgrade of persistent state rather than a newly created DB.
LEGACY_SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0, is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
    csrf_token TEXT NOT NULL, expires_at REAL NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE TABLE tasks (
    id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL, notes TEXT NOT NULL, location TEXT NOT NULL,
    due_date TEXT, due_time TEXT, priority TEXT NOT NULL, tags TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, completed_at TEXT
);
CREATE INDEX tasks_owner ON tasks(owner_id);
CREATE TABLE shares (
    task_id INTEGER NOT NULL REFERENCES tasks(id), user_id INTEGER NOT NULL REFERENCES users(id),
    permission TEXT NOT NULL CHECK(permission IN ('view','edit')), PRIMARY KEY(task_id,user_id)
);
CREATE INDEX shares_user ON shares(user_id);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def old_database(data_dir, *, administrator=None):
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(data_dir / "gid.sqlite3") as db:
        db.executescript(LEGACY_SCHEMA)
        db.executemany("INSERT INTO settings(key,value) VALUES(?,?)", [("app_name", "Existing Tasks"), ("timezone", "Europe/London")])
        if administrator:
            db.executemany("INSERT INTO users(id,username,display_name,password_hash,is_admin,created_at) VALUES(?,?,?,?,?,?)", [(1, administrator, "Existing Admin", password_hash(PASSWORD), 1, now), (2, "consumer", "Consumer", password_hash(PASSWORD), 0, now)])
            db.executemany("INSERT INTO tasks(id,owner_id,title,notes,location,due_date,due_time,priority,tags,created_at,updated_at,completed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", [(1, 1, "Completed legacy task", "Keep my notes", "Home", "2026-10-01", "09:00", "high", '["Home"]', now, now, now), (2, 2, "Shared legacy task", "Keep my sharing", "Office", None, None, "normal", "[]", now, now, None)])
            db.execute("INSERT INTO shares(task_id,user_id,permission) VALUES(2,1,'edit')")
            db.execute("INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at) VALUES(?,?,?,?)", (token_hash("legacy-session-cookie"), 1, "legacy-csrf-token", (datetime.now(timezone.utc) + timedelta(days=1)).timestamp()))
        snapshots = {table: db.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall() for table in ("users", "sessions", "tasks", "shares", "settings")}
    (data_dir / "setup-token.txt").write_text("obsolete-private-setup-code\n")
    return snapshots


def test_upgrade_unconfigured_v010_database_seeds_admin_and_removes_setup_token(tmp_path, caplog):
    old_database(tmp_path)
    with TestClient(create_app(tmp_path)) as client:
        assert not (tmp_path / "setup-token.txt").exists()
        assert "obsolete-private-setup-code" not in caplog.text and "setup code" not in caplog.text.lower()
        assert client.get("/api/bootstrap").json() == {"setup_required": False, "initial_password_change_required": True, "app_name": "Existing Tasks", "timezone": "Europe/London"}
        assert signin(client, "admin", "admin")["user"]["must_change_password"] is True
        assert client.get("/api/tasks").json() == {"detail": PASSWORD_REQUIRED}
        with sqlite3.connect(tmp_path / "gid.sqlite3") as db:
            column = next(row for row in db.execute("PRAGMA table_info(users)") if row[1] == "must_change_password")
            assert column[3] == 1 and column[4] == "0"
            assert db.execute("SELECT username,is_admin,is_active,must_change_password FROM users").fetchall() == [("admin", 1, 1, 1)]


@pytest.mark.parametrize("administrator", ["admin", "operator"])
def test_upgrade_configured_v010_preserves_accounts_passwords_sessions_tasks_shares_and_settings(tmp_path, administrator):
    snapshots = old_database(tmp_path, administrator=administrator)
    with TestClient(create_app(tmp_path)) as client:
        assert not (tmp_path / "setup-token.txt").exists()
        assert client.get("/api/bootstrap").json() == {"setup_required": False, "initial_password_change_required": False, "app_name": "Existing Tasks", "timezone": "Europe/London"}
        client.cookies.set(COOKIE_NAME, "legacy-session-cookie")
        existing = client.get("/api/me")
        assert existing.status_code == 200 and existing.json()["user"]["must_change_password"] is False
        assert existing.json()["csrf_token"] == "legacy-csrf-token"
        tasks = client.get("/api/tasks?view=all").json()["tasks"]
        assert {task["title"] for task in tasks} == {"Completed legacy task", "Shared legacy task"}
        assert next(task for task in tasks if task["id"] == 1)["completed_at"]
        assert next(task for task in tasks if task["id"] == 2)["permission"] == "edit"
        with sqlite3.connect(tmp_path / "gid.sqlite3") as db:
            assert db.execute("SELECT id,username,display_name,password_hash,is_admin,is_active,created_at FROM users ORDER BY id").fetchall() == snapshots["users"]
            assert db.execute("SELECT must_change_password FROM users ORDER BY id").fetchall() == [(0,), (0,)]
            for table in ("sessions", "tasks", "shares", "settings"):
                assert db.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall() == snapshots[table]
        assert client.post("/api/bootstrap", json={"username": "admin", "password": "admin"}).status_code in {404, 405}
        assert client.post("/api/login", json={"username": "admin", "password": "admin"}).status_code == 401
        logged = signin(client, administrator)
        assert logged["user"]["must_change_password"] is False
        assert add_user(client, logged, "newconsumer")["must_change_password"] is False
        assert signin(client, "newconsumer")["user"]["must_change_password"] is False
        assert client.get("/api/tasks").status_code == 200
    with TestClient(create_app(tmp_path)) as restarted:
        assert restarted.get("/api/bootstrap").json()["initial_password_change_required"] is False
        assert restarted.post("/api/login", json={"username": "admin", "password": "admin"}).status_code == 401
        assert signin(restarted, administrator)["user"]["must_change_password"] is False


def test_signin_rate_limit_and_session_expiration(site):
    application, client, data_dir = site
    configure_admin(client)
    for _ in range(10):
        assert client.post("/api/login", json={"username": "nobody", "password": "bad"}).status_code == 401
    assert client.post("/api/login", json={"username": "nobody", "password": "bad"}).status_code == 429
    with application.state.runtime.db() as db:
        db.execute("UPDATE sessions SET expires_at=0")
    assert client.get("/api/me").status_code == 401


@pytest.mark.parametrize("payload", [
    {"title": " "}, {"title": "x" * 201}, {"title": "Valid", "notes": "x" * 20001},
    {"title": "Valid", "location": "x" * 301}, {"title": "Valid", "due_date": "2026-02-30"},
    {"title": "Valid", "due_date": "2026-2-3"}, {"title": "Valid", "due_time": "12:00"},
    {"title": "Valid", "due_date": "2026-01-01", "due_time": "24:00"},
    {"title": "Valid", "due_date": "2026-01-01", "due_time": "12:00:00"},
    {"title": "Valid", "tags": ["x"] * 11}, {"title": "Valid", "tags": ["x" * 33]},
    {"title": "Valid", "tags": [""]}, {"title": "Valid", "priority": "urgent"},
    {"title": "Valid", "owner_id": 100}, {"title": "Valid", "notes": "bad\x00text"},
    {"title": "Valid", "tags": [1]},
])
def test_task_validation(site, payload):
    _, client, data_dir = site
    auth = configure_admin(client)
    assert client.post("/api/tasks", headers=headers(auth), json=payload).status_code == 422


def test_patch_validation_merges_due_fields_and_forbids_mutable_ownership(site):
    _, client, data_dir = site
    admin = configure_admin(client)
    task = new_task(client, admin, due_date="2026-10-19", due_time="10:00", tags=["Home", "home"])
    assert task["tags"] == ["Home"]
    url = f"/api/tasks/{task['id']}"
    for payload in ({"title": None}, {"title": ""}, {"notes": None}, {"tags": None}, {"title": "x" * 201}, {"due_date": None}, {"owner_id": 123}, {"completed_at": "2026-10-19"}):
        assert client.patch(url, headers=headers(admin), json=payload).status_code == 422
    assert client.patch(url, headers=headers(admin), json={"due_date": None, "due_time": None}).status_code == 200
    assert client.patch(url, headers=headers(admin), json={"due_time": "10:00"}).status_code == 422


def test_account_and_settings_validation(site):
    _, client, data_dir = site
    admin = configure_admin(client)
    for update in ({"app_name": " ", "timezone": "UTC"}, {"app_name": "GID", "timezone": "Invalid/Zone"}):
        assert client.put("/api/admin/settings", headers=headers(admin), json=update).status_code == 422
    for fields in ({"username": "bad space"}, {"username": "xx"}, {"display_name": " "}, {"password": "short"}, {"is_admin": 1}):
        body = {"username": "consumer", "display_name": "Consumer", "password": PASSWORD, **fields}
        result = client.post("/api/admin/users", headers=headers(admin), json=body)
        assert result.status_code == 422
        assert PASSWORD not in result.text
    user = add_user(client, admin, "consumer")
    assert client.post("/api/admin/users", headers=headers(admin), json={"username": "CONSUMER", "display_name": "Duplicate", "password": PASSWORD}).status_code == 409
    assert client.patch(f"/api/admin/users/{user['id']}", headers=headers(admin), json={"is_active": None}).status_code == 422


def test_request_body_limit_bounds_regular_and_streamed_requests(site):
    _, client, data_dir = site
    admin = configure_admin(client)
    huge = '{"title":"' + "x" * (128 * 1024) + '"}'
    response = client.post("/api/tasks", headers={**headers(admin), "Content-Type": "application/json"}, content=huge)
    assert response.status_code == 413
    assert response.headers["x-content-type-options"] == "nosniff"
    chunks = (chunk for chunk in [b'{"title":"', b"x" * (128 * 1024), b'"}'])
    assert client.post("/api/tasks", headers={**headers(admin), "Content-Type": "application/json"}, content=chunks).status_code == 413
    assert client.get("/api/tasks").json()["tasks"] == []

