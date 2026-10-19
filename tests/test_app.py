"""Behavior and security regressions for GID's shared task boundaries."""

import csv
import io
import sqlite3
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient

from gid.app import COOKIE_NAME, create_app


PASSWORD = "correct horse battery staple"


@pytest.fixture
def site(tmp_path):
    application = create_app(tmp_path)
    with TestClient(application) as client:
        yield application, client, tmp_path


def bootstrap(client, data_dir, username="admin"):
    response = client.post("/api/bootstrap", json={"setup_token": (data_dir / "setup-token.txt").read_text().strip(), "username": username, "display_name": "Administrator", "password": PASSWORD})
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


def test_bootstrap_requires_secret_and_cannot_run_twice(site):
    application, client, data_dir = site
    initial = client.get("/api/bootstrap")
    assert initial.json() == {"setup_required": True, "app_name": "Get It Done", "timezone": "America/New_York"}
    assert "setup_token" not in initial.text
    assert client.get("/api/me").status_code == 401
    bad = client.post("/api/bootstrap", json={"setup_token": "wrong", "username": "admin", "display_name": "Admin", "password": PASSWORD})
    assert bad.status_code == 403
    unicode_token = client.post("/api/bootstrap", json={"setup_token": "wrong-ü", "username": "admin", "display_name": "Admin", "password": PASSWORD})
    assert unicode_token.status_code == 403
    admin = bootstrap(client, data_dir)
    assert admin["user"]["is_admin"] is True
    assert admin["csrf_token"]
    assert not (data_dir / "setup-token.txt").exists()
    assert client.get("/api/bootstrap").json()["setup_required"] is False
    assert client.post("/api/bootstrap", json={"setup_token": "wrong", "username": "other", "display_name": "Other", "password": PASSWORD}).status_code == 409
    cookie = client.cookies.get(COOKIE_NAME)
    with sqlite3.connect(data_dir / "gid.sqlite3") as db:
        stored = db.execute("SELECT password_hash FROM users").fetchone()[0]
        stored_session = db.execute("SELECT token_hash FROM sessions").fetchone()[0]
    assert stored.startswith("scrypt$") and PASSWORD not in stored
    assert cookie not in stored_session
    assert client.get("/api/me").json()["user"]["username"] == "admin"
    assert (data_dir.stat().st_mode & 0o777) == 0o700
    assert ((data_dir / "gid.sqlite3").stat().st_mode & 0o777) == 0o600


def test_csrf_origin_headers_and_cookie_policy(site):
    _, client, data_dir = site
    response = client.post("/api/bootstrap", json={"setup_token": (data_dir / "setup-token.txt").read_text().strip(), "username": "admin", "display_name": "Admin", "password": PASSWORD})
    auth = response.json()
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
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
    admin = bootstrap(client, data_dir)
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
    admin = bootstrap(client, data_dir)
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
    admin = bootstrap(client, data_dir)
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
    admin = bootstrap(client, data_dir)
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
    admin = bootstrap(client, data_dir)
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
    admin = bootstrap(client, data_dir)
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
    admin = bootstrap(client, data_dir)
    with TestClient(application) as other:
        signin(other, "admin")
        assert client.post("/api/account/password", headers=headers(admin), json={"current_password": "wrong", "new_password": "replacement strong password"}).status_code == 400
        assert client.post("/api/account/password", headers=headers(admin), json={"current_password": PASSWORD, "new_password": "replacement strong password"}).status_code == 200
        assert other.get("/api/me").status_code == 401
        assert client.get("/api/me").status_code == 200
        assert other.post("/api/login", json={"username": "admin", "password": PASSWORD}).status_code == 401
        signin(other, "admin", "replacement strong password")
    assert client.post("/api/logout", headers=headers(admin)).status_code == 200
    assert client.get("/api/me").status_code == 401


def test_signin_rate_limit_and_session_expiration(site):
    application, client, data_dir = site
    bootstrap(client, data_dir)
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
    auth = bootstrap(client, data_dir)
    assert client.post("/api/tasks", headers=headers(auth), json=payload).status_code == 422


def test_patch_validation_merges_due_fields_and_forbids_mutable_ownership(site):
    _, client, data_dir = site
    admin = bootstrap(client, data_dir)
    task = new_task(client, admin, due_date="2026-10-19", due_time="10:00", tags=["Home", "home"])
    assert task["tags"] == ["Home"]
    url = f"/api/tasks/{task['id']}"
    for payload in ({"title": None}, {"title": ""}, {"notes": None}, {"tags": None}, {"title": "x" * 201}, {"due_date": None}, {"owner_id": 123}, {"completed_at": "2026-10-19"}):
        assert client.patch(url, headers=headers(admin), json=payload).status_code == 422
    assert client.patch(url, headers=headers(admin), json={"due_date": None, "due_time": None}).status_code == 200
    assert client.patch(url, headers=headers(admin), json={"due_time": "10:00"}).status_code == 422


def test_account_and_settings_validation(site):
    _, client, data_dir = site
    admin = bootstrap(client, data_dir)
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
    admin = bootstrap(client, data_dir)
    huge = '{"title":"' + "x" * (128 * 1024) + '"}'
    response = client.post("/api/tasks", headers={**headers(admin), "Content-Type": "application/json"}, content=huge)
    assert response.status_code == 413
    assert response.headers["x-content-type-options"] == "nosniff"
    chunks = (chunk for chunk in [b'{"title":"', b"x" * (128 * 1024), b'"}'])
    assert client.post("/api/tasks", headers={**headers(admin), "Content-Type": "application/json"}, content=chunks).status_code == 413
    assert client.get("/api/tasks").json()["tasks"] == []

