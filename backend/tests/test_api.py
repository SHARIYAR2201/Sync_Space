import os, tempfile
os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.mkdtemp()}/t.db"
os.environ["AUTH_RATE_LIMIT"] = "1000"
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
import pytest
from app.main import app
c = TestClient(app)

def reg(email, name="Test User"):
    r = c.post("/api/v1/auth/register", json={"name": name, "email": email, "password": "password123"}); assert r.status_code == 201, r.text
    return r.json(), {"Authorization": "Bearer " + r.json()["access_token"]}

def test_auth_flow_and_refresh_rotation():
    d, h = reg("a@x.io")
    assert c.get("/api/v1/auth/me", headers=h).json()["role"] == "Owner"
    assert c.post("/api/v1/auth/login", json={"email": "a@x.io", "password": "bad"}).status_code == 401
    r1 = c.post("/api/v1/auth/refresh", json={"refresh_token": d["refresh_token"]}); assert r1.status_code == 200
    assert c.post("/api/v1/auth/refresh", json={"refresh_token": d["refresh_token"]}).status_code == 401   # reuse
    assert c.post("/api/v1/auth/refresh", json={"refresh_token": r1.json()["refresh_token"]}).status_code == 401  # family revoked
    assert c.post("/api/v1/auth/register", json={"name": "d", "email": "a@x.io", "password": "password123"}).status_code == 409
    assert c.get("/api/v1/tasks").status_code == 401

def test_tasks_dashboard_and_workspace_isolation():
    _, ha = reg("owner@x.io"); _, hb = reg("other@x.io")
    p = c.post("/api/v1/projects", json={"name": "P"}, headers=ha).json()
    t = c.post("/api/v1/tasks", json={"title": "T", "project_id": p["id"], "due_date": "2020-01-01"}, headers=ha).json()
    assert c.get("/api/v1/dashboard", headers=ha).json()["overdue"] == 1
    c.patch(f"/api/v1/tasks/{t['id']}", json={"status": "Done"}, headers=ha)
    assert c.get("/api/v1/projects", headers=ha).json()[0]["progress"] == 100
    # other workspace cannot see or touch it
    assert c.get("/api/v1/tasks", headers=hb).json() == []
    assert c.patch(f"/api/v1/tasks/{t['id']}", json={"status": "Todo"}, headers=hb).status_code == 404
    assert c.post("/api/v1/tasks", json={"title": "x", "project_id": p["id"]}, headers=hb).status_code == 404

def test_roles_and_invitations():
    _, ho = reg("boss@x.io"); _, hm = reg("mem@x.io", "Mem")
    inv = c.post("/api/v1/invitations", json={"email": "mem@x.io", "role": "Member"}, headers=ho).json()
    assert c.post("/api/v1/invitations/accept", json={"token": inv["dev_token"]}, headers=hm).status_code == 200
    assert c.post("/api/v1/invitations/accept", json={"token": inv["dev_token"]}, headers=hm).status_code == 400  # single use
    # mem's first workspace is still their own (Owner); a pure Member is checked below via a second invitee
    _, hz = reg("z@x.io"); inv2 = c.post("/api/v1/invitations", json={"email": "z@x.io", "role": "Member"}, headers=ho).json()
    assert c.post("/api/v1/invitations/accept", json={"token": inv2["dev_token"]}, headers=hz).status_code == 200

def test_chat_persist_and_ws_auth():
    d, h = reg("chat@x.io")
    ch = c.get("/api/v1/channels", headers=h).json()[0]
    with pytest.raises(WebSocketDisconnect): 
        with c.websocket_connect(f"/api/v1/ws?token=bad&channel_id={ch['id']}"): pass
    with c.websocket_connect(f"/api/v1/ws?token={d['access_token']}&channel_id={ch['id']}") as ws:
        assert c.post(f"/api/v1/channels/{ch['id']}/messages", json={"body": "hi"}, headers=h).status_code == 201
        assert ws.receive_json()["data"]["text"] == "hi"
    assert c.get(f"/api/v1/channels/{ch['id']}/messages", headers=h).json()[0]["text"] == "hi"

def test_custom_404_and_validation():
    assert c.get("/nope").status_code == 404
    assert c.post("/api/v1/auth/register", json={"name": "x", "email": "bad", "password": "short"}).status_code == 422

def test_comments_files_dm_search():
    os.environ["UPLOAD_DIR"] = tempfile.mkdtemp()
    import app.extras as ex; ex.UPLOAD_DIR = os.environ["UPLOAD_DIR"]
    _, ha = reg("own2@x.io", "Olga Owner"); _, hb = reg("out@x.io", "Outsider")
    p = c.post("/api/v1/projects", json={"name": "Searchable Project"}, headers=ha).json()
    t = c.post("/api/v1/tasks", json={"title": "Write docs", "project_id": p["id"]}, headers=ha).json()
    assert c.post(f"/api/v1/tasks/{t['id']}/comments", json={"body": "hi @olga"}, headers=ha).status_code == 201
    assert c.get(f"/api/v1/tasks/{t['id']}/comments", headers=ha).json()[0]["author"] == "Olga Owner"
    assert c.get(f"/api/v1/tasks/{t['id']}/comments", headers=hb).status_code == 404
    up = lambda n, d, h: c.post(f"/api/v1/tasks/{t['id']}/attachments", files={"file": (n, d)}, headers=h)
    assert up("../../evil.exe", b"x", ha).status_code == 415
    assert up("fake.png", b"not a png", ha).status_code == 415
    ok = up("pic.png", b"\x89PNG....", ha); assert ok.status_code == 201
    assert c.get(f"/api/v1/attachments/{ok.json()['id']}", headers=ha).status_code == 200
    assert c.get(f"/api/v1/attachments/{ok.json()['id']}", headers=hb).status_code == 404  # cross-workspace denial
    assert [x["name"] for x in c.get("/api/v1/search?q=searchable", headers=ha).json()["projects"]] == ["Searchable Project"]
    assert c.get("/api/v1/search?q=searchable", headers=hb).json()["projects"] == []
    assert c.post("/api/v1/dm/9999", json={"body": "x"}, headers=ha).status_code == 404
