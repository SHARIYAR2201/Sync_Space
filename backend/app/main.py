"""SyncSpace API. Routes are grouped by area; all workspace data is scoped by the caller's membership."""
import os, secrets, time, logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone, date
from typing import Literal
import jwt
from fastapi import FastAPI, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .core import *

log = logging.getLogger("syncspace")
app = FastAPI(title="SyncSpace API", version="1.0")
FRONTEND = os.getenv("FRONTEND_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))
STATUSES = ["Backlog", "Todo", "In Progress", "In Review", "Done", "Cancelled"]
PRIORITIES = ["Low", "Medium", "High", "Urgent"]
ROLES = ["Owner", "Admin", "Manager", "Member"]

def db():
    with SessionLocal() as s: yield s

# ---------- simple per-IP rate limit for auth endpoints ----------
_hits = defaultdict(list)
def limit(request: Request):
    k = (request.client.host if request.client else "?", request.url.path)
    t = time.time(); _hits[k] = [x for x in _hits[k] if t - x < 60]
    if len(_hits[k]) >= int(os.getenv("AUTH_RATE_LIMIT", "20")):
        raise HTTPException(429, "Too many attempts. Please wait a minute and try again.")
    _hits[k].append(t)

# ---------- auth dependencies ----------
def current_user(request: Request, s: Session = Depends(db)) -> User:
    h = request.headers.get("authorization", "")
    try: uid = read_access(h.removeprefix("Bearer ").strip())
    except Exception: raise HTTPException(401, "Session expired. Please sign in again.")
    u = s.get(User, uid)
    if not u: raise HTTPException(401, "Account not found.")
    return u

def membership(u: User = Depends(current_user), s: Session = Depends(db)) -> Membership:
    m = s.scalars(select(Membership).where(Membership.user_id == u.id).order_by(Membership.id)).first()
    if not m: raise HTTPException(403, "You are not a member of any workspace.")
    return m

def need(m: Membership, *roles):
    if m.role not in roles: raise HTTPException(403, "Your role does not allow this action.")

def log_activity(s, ws, text): s.add(Activity(workspace_id=ws, text=text[:300]))
def notify(s, uid, text): s.add(Notification(user_id=uid, text=text[:300]))

# ---------- schemas ----------
class Register(BaseModel):
    name: str = Field(min_length=1, max_length=120); email: EmailStr; password: str = Field(min_length=8, max_length=128)
class Login(BaseModel): email: EmailStr; password: str
class Refresh(BaseModel): refresh_token: str
class Forgot(BaseModel): email: EmailStr
class Reset(BaseModel): token: str; password: str = Field(min_length=8, max_length=128)
class ProfileIn(BaseModel): name: str = Field(min_length=1, max_length=120)
class InviteIn(BaseModel): email: EmailStr; role: Literal["Admin", "Manager", "Member"] = "Member"
class AcceptIn(BaseModel): token: str
class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=120); description: str = ""
    status: Literal["Planning", "Active", "On Hold", "Completed", "Archived"] = "Active"
class TaskIn(BaseModel):
    title: str = Field(min_length=1, max_length=200); project_id: int; description: str = ""
    assignee_id: int | None = None; priority: Literal["Low", "Medium", "High", "Urgent"] = "Medium"
    status: Literal["Backlog", "Todo", "In Progress", "In Review", "Done", "Cancelled"] = "Backlog"
    due_date: date | None = None
class TaskPatch(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=200)
    status: Literal["Backlog", "Todo", "In Progress", "In Review", "Done", "Cancelled"] | None = None
    priority: Literal["Low", "Medium", "High", "Urgent"] | None = None
    assignee_id: int | None = None; due_date: date | None = None
class MsgIn(BaseModel): body: str = Field(min_length=1, max_length=4000)
class AskIn(BaseModel): question: str = Field(min_length=1, max_length=500)

def udict(u): return {"id": u.id, "name": u.name, "email": u.email}
def issue_tokens(s, u):
    raw = secrets.token_urlsafe(48)
    s.add(RefreshToken(user_id=u.id, token_hash=sha(raw), expires_at=now() + timedelta(days=REFRESH_DAYS)))
    s.commit()
    return {"access_token": make_access(u.id), "refresh_token": raw, "user": udict(u)}

def new_workspace(s, u, name):
    w = Workspace(name=name); s.add(w); s.flush()
    s.add(Membership(workspace_id=w.id, user_id=u.id, role="Owner"))
    for c in ("general", "engineering", "design"): s.add(Channel(workspace_id=w.id, name=c))
    log_activity(s, w.id, f"{u.name} created the workspace"); return w

# ---------- AUTH ----------
@app.post("/api/v1/auth/register", status_code=201, dependencies=[Depends(limit)])
def register(b: Register, s: Session = Depends(db)):
    if s.scalars(select(User).where(User.email == b.email.lower())).first():
        raise HTTPException(409, "An account with this email already exists.")
    u = User(email=b.email.lower(), name=b.name.strip(), password_hash=hash_password(b.password))
    s.add(u); s.flush(); new_workspace(s, u, f"{u.name}'s workspace"); s.commit()
    return issue_tokens(s, u)

@app.post("/api/v1/auth/login", dependencies=[Depends(limit)])
def login(b: Login, s: Session = Depends(db)):
    u = s.scalars(select(User).where(User.email == b.email.lower())).first()
    if not u or not verify_password(b.password, u.password_hash):
        raise HTTPException(401, "Incorrect email or password.")
    return issue_tokens(s, u)

@app.post("/api/v1/auth/refresh", dependencies=[Depends(limit)])
def refresh(b: Refresh, s: Session = Depends(db)):
    t = s.scalars(select(RefreshToken).where(RefreshToken.token_hash == sha(b.refresh_token))).first()
    if not t: raise HTTPException(401, "Invalid session.")
    if t.revoked:  # reuse of a rotated token => assume theft, revoke the whole family
        for x in s.scalars(select(RefreshToken).where(RefreshToken.user_id == t.user_id)): x.revoked = True
        s.commit(); raise HTTPException(401, "Session revoked. Please sign in again.")
    if t.expires_at.replace(tzinfo=timezone.utc) < now(): raise HTTPException(401, "Session expired.")
    t.revoked = True; s.commit()
    return issue_tokens(s, s.get(User, t.user_id))

@app.post("/api/v1/auth/logout")
def logout(b: Refresh, s: Session = Depends(db)):
    t = s.scalars(select(RefreshToken).where(RefreshToken.token_hash == sha(b.refresh_token))).first()
    if t: t.revoked = True; s.commit()
    return {"ok": True}

@app.post("/api/v1/auth/forgot", dependencies=[Depends(limit)])
def forgot(b: Forgot, s: Session = Depends(db)):
    u = s.scalars(select(User).where(User.email == b.email.lower())).first()
    if u:
        raw = secrets.token_urlsafe(32)
        s.add(ResetToken(user_id=u.id, token_hash=sha(raw), expires_at=now() + timedelta(hours=1))); s.commit()
        # No email provider configured: log for development instead of claiming an email was sent.
        log.warning("DEV password reset token for %s: %s", u.email, raw)
    return {"message": "If that email is registered, reset instructions have been generated."}  # generic: no enumeration

@app.post("/api/v1/auth/reset", dependencies=[Depends(limit)])
def reset(b: Reset, s: Session = Depends(db)):
    t = s.scalars(select(ResetToken).where(ResetToken.token_hash == sha(b.token))).first()
    if not t or t.used or t.expires_at.replace(tzinfo=timezone.utc) < now():
        raise HTTPException(400, "Reset link is invalid or has expired.")
    s.get(User, t.user_id).password_hash = hash_password(b.password); t.used = True
    for x in s.scalars(select(RefreshToken).where(RefreshToken.user_id == t.user_id)): x.revoked = True
    s.commit(); return {"message": "Password updated. You can now sign in."}

@app.get("/api/v1/auth/me")
def me(u: User = Depends(current_user), m: Membership = Depends(membership), s: Session = Depends(db)):
    return {**udict(u), "role": m.role, "workspace": s.get(Workspace, m.workspace_id).name}

@app.patch("/api/v1/auth/me")
def edit_me(b: ProfileIn, u: User = Depends(current_user), s: Session = Depends(db)):
    u.name = b.name.strip(); s.merge(u); s.commit(); return udict(u)

# ---------- MEMBERS / INVITATIONS ----------
@app.get("/api/v1/members")
def members(m: Membership = Depends(membership), s: Session = Depends(db)):
    rows = s.scalars(select(Membership).where(Membership.workspace_id == m.workspace_id)).unique().all()
    inv = s.scalars(select(Invitation).where(Invitation.workspace_id == m.workspace_id, Invitation.used == False)).all()  # noqa
    return [{**udict(r.user), "role": r.role, "status": "Active"} for r in rows] + \
           [{"id": -i.id, "name": i.email.split("@")[0], "email": i.email, "role": i.role, "status": "Pending"} for i in inv]

@app.post("/api/v1/invitations", status_code=201)
def invite(b: InviteIn, m: Membership = Depends(membership), s: Session = Depends(db)):
    need(m, "Owner", "Admin")
    raw = secrets.token_urlsafe(32)
    s.add(Invitation(workspace_id=m.workspace_id, email=b.email.lower(), role=b.role, token_hash=sha(raw),
                     expires_at=now() + timedelta(days=7)))
    log_activity(s, m.workspace_id, f"Invitation sent to {b.email}"); s.commit()
    log.warning("DEV invitation token for %s: %s", b.email, raw)  # replace with email provider
    return {"message": f"Invitation created for {b.email}.", "dev_token": raw if ENV != "production" else None}

@app.post("/api/v1/invitations/accept")
def accept(b: AcceptIn, u: User = Depends(current_user), s: Session = Depends(db)):
    i = s.scalars(select(Invitation).where(Invitation.token_hash == sha(b.token))).first()
    if not i or i.used or i.expires_at.replace(tzinfo=timezone.utc) < now() or i.email != u.email:
        raise HTTPException(400, "Invitation is invalid, expired, or for a different email.")
    if not s.scalars(select(Membership).where(Membership.workspace_id == i.workspace_id, Membership.user_id == u.id)).first():
        s.add(Membership(workspace_id=i.workspace_id, user_id=u.id, role=i.role))
    i.used = True; log_activity(s, i.workspace_id, f"{u.name} joined the workspace"); s.commit()
    return {"message": "Invitation accepted."}

@app.delete("/api/v1/members/{uid}")
def remove_member(uid: int, m: Membership = Depends(membership), s: Session = Depends(db)):
    need(m, "Owner", "Admin")
    t = s.scalars(select(Membership).where(Membership.workspace_id == m.workspace_id, Membership.user_id == uid)).first()
    if not t: raise HTTPException(404, "Member not found.")
    if t.role == "Owner" or (t.role == "Admin" and m.role != "Owner"): raise HTTPException(403, "You cannot remove this member.")
    s.delete(t); s.commit(); return {"ok": True}

# ---------- PROJECTS ----------
def progress(s, pid):
    rows = dict(s.execute(select(Task.status, func.count()).where(Task.project_id == pid).group_by(Task.status)).all())
    total = sum(v for k, v in rows.items() if k != "Cancelled")  # cancelled tasks excluded from progress
    return round(100 * rows.get("Done", 0) / total) if total else 0

@app.get("/api/v1/projects")
def projects(m: Membership = Depends(membership), s: Session = Depends(db)):
    ps = s.scalars(select(Project).where(Project.workspace_id == m.workspace_id, Project.status != "Archived")).all()
    return [{"id": p.id, "name": p.name, "description": p.description, "status": p.status, "progress": progress(s, p.id)} for p in ps]

@app.post("/api/v1/projects", status_code=201)
def create_project(b: ProjectIn, u: User = Depends(current_user), m: Membership = Depends(membership), s: Session = Depends(db)):
    need(m, "Owner", "Admin", "Manager")
    p = Project(workspace_id=m.workspace_id, name=b.name.strip(), description=b.description, status=b.status, owner_id=u.id)
    s.add(p); log_activity(s, m.workspace_id, f"{u.name} created project {p.name}"); s.commit()
    return {"id": p.id, "name": p.name, "status": p.status, "progress": 0}

@app.delete("/api/v1/projects/{pid}")
def delete_project(pid: int, m: Membership = Depends(membership), s: Session = Depends(db)):
    need(m, "Owner", "Admin")
    p = s.get(Project, pid)
    if not p or p.workspace_id != m.workspace_id: raise HTTPException(404, "Project not found.")
    for t in s.scalars(select(Task).where(Task.project_id == pid)): s.delete(t)
    s.delete(p); s.commit(); return {"ok": True}

# ---------- TASKS ----------
def tdict(t, names, pnames):
    return {"id": t.id, "title": t.title, "status": t.status, "priority": t.priority, "project_id": t.project_id,
            "project": pnames.get(t.project_id, ""), "assignee_id": t.assignee_id,
            "assignee": names.get(t.assignee_id, "Unassigned"), "dueDate": t.due_date.date().isoformat() if t.due_date else "—"}

def lookups(s, ws):
    names = {r.user_id: r.user.name for r in s.scalars(select(Membership).where(Membership.workspace_id == ws)).unique()}
    return names, {p.id: p.name for p in s.scalars(select(Project).where(Project.workspace_id == ws))}

def to_dt(d): return datetime(d.year, d.month, d.day, tzinfo=timezone.utc) if d else None

def check_assignee(s, ws, uid):
    if uid is not None and not s.scalars(select(Membership).where(Membership.workspace_id == ws, Membership.user_id == uid)).first():
        raise HTTPException(422, "Assignee must be a member of this workspace.")

@app.get("/api/v1/tasks")
def tasks(mine: bool = False, status: str | None = None, project_id: int | None = None,
          limit: int = Query(200, le=500), offset: int = 0,
          u: User = Depends(current_user), m: Membership = Depends(membership), s: Session = Depends(db)):
    q = select(Task).where(Task.workspace_id == m.workspace_id)
    if mine: q = q.where(Task.assignee_id == u.id)
    if status: q = q.where(Task.status == status)
    if project_id: q = q.where(Task.project_id == project_id)
    names, pn = lookups(s, m.workspace_id)
    return [tdict(t, names, pn) for t in s.scalars(q.order_by(Task.id.desc()).limit(limit).offset(offset))]

@app.post("/api/v1/tasks", status_code=201)
def create_task(b: TaskIn, u: User = Depends(current_user), m: Membership = Depends(membership), s: Session = Depends(db)):
    p = s.get(Project, b.project_id)
    if not p or p.workspace_id != m.workspace_id: raise HTTPException(404, "Project not found.")
    check_assignee(s, m.workspace_id, b.assignee_id)
    t = Task(workspace_id=m.workspace_id, project_id=p.id, title=b.title.strip(), description=b.description, status=b.status,
             priority=b.priority, assignee_id=b.assignee_id, creator_id=u.id, due_date=to_dt(b.due_date),
             completed_at=now() if b.status == "Done" else None)
    s.add(t); log_activity(s, m.workspace_id, f"{u.name} created task {t.title}")
    if b.assignee_id and b.assignee_id != u.id: notify(s, b.assignee_id, f"{u.name} assigned you: {t.title}")
    s.commit(); names, pn = lookups(s, m.workspace_id); return tdict(t, names, pn)

@app.patch("/api/v1/tasks/{tid}")
def patch_task(tid: int, b: TaskPatch, u: User = Depends(current_user), m: Membership = Depends(membership), s: Session = Depends(db)):
    t = s.get(Task, tid)
    if not t or t.workspace_id != m.workspace_id: raise HTTPException(404, "Task not found.")
    d = b.model_dump(exclude_unset=True)
    if "assignee_id" in d:
        check_assignee(s, m.workspace_id, d["assignee_id"]); t.assignee_id = d["assignee_id"]
        if d["assignee_id"] and d["assignee_id"] != u.id: notify(s, d["assignee_id"], f"{u.name} assigned you: {t.title}")
    if "due_date" in d: t.due_date = to_dt(d["due_date"])
    for k in ("title", "priority"):
        if d.get(k) is not None: setattr(t, k, d[k])
    if d.get("status") and d["status"] != t.status:
        t.status = d["status"]; t.completed_at = now() if t.status == "Done" else None
        log_activity(s, m.workspace_id, f"{u.name} moved {t.title} to {t.status}")
    s.commit(); names, pn = lookups(s, m.workspace_id); return tdict(t, names, pn)

@app.delete("/api/v1/tasks/{tid}")
def delete_task(tid: int, m: Membership = Depends(membership), s: Session = Depends(db)):
    t = s.get(Task, tid)
    if not t or t.workspace_id != m.workspace_id: raise HTTPException(404, "Task not found.")
    s.delete(t); s.commit(); return {"ok": True}

# ---------- CHANNELS / MESSAGES + WebSocket ----------
class Hub:
    def __init__(self): self.rooms = defaultdict(set)
    async def send(self, cid, data):
        for ws in list(self.rooms[cid]):
            try: await ws.send_json(data)
            except Exception: self.rooms[cid].discard(ws)
hub = Hub()

def channel_for(s, m, cid):
    c = s.get(Channel, cid)
    if not c or c.workspace_id != m.workspace_id: raise HTTPException(404, "Channel not found.")
    return c

@app.get("/api/v1/channels")
def channels(m: Membership = Depends(membership), s: Session = Depends(db)):
    return [{"id": c.id, "name": "#" + c.name} for c in s.scalars(select(Channel).where(Channel.workspace_id == m.workspace_id))]

def mdict(x, name): return {"id": x.id, "sender": name, "text": x.body, "time": x.created_at.strftime("%b %d, %H:%M"),
                            "avatar": "".join(w[0] for w in name.split()[:2]).upper()}

@app.get("/api/v1/channels/{cid}/messages")
def history(cid: int, before: int | None = None, limit: int = Query(50, le=100),
            m: Membership = Depends(membership), s: Session = Depends(db)):
    channel_for(s, m, cid); names, _ = lookups(s, m.workspace_id)
    q = select(Message).where(Message.channel_id == cid)
    if before: q = q.where(Message.id < before)
    rows = list(s.scalars(q.order_by(Message.id.desc()).limit(limit)))[::-1]
    return [mdict(x, names.get(x.user_id, "Former member")) for x in rows]

@app.post("/api/v1/channels/{cid}/messages", status_code=201)
async def post_message(cid: int, b: MsgIn, u: User = Depends(current_user), m: Membership = Depends(membership), s: Session = Depends(db)):
    channel_for(s, m, cid)
    x = Message(channel_id=cid, user_id=u.id, body=b.body.strip()); s.add(x); s.commit()  # persist BEFORE broadcast
    out = mdict(x, u.name); await hub.send(cid, {"type": "message.created", "channel_id": cid, "data": out}); return out

@app.websocket("/api/v1/ws")
async def ws_endpoint(ws: WebSocket, token: str, channel_id: int):
    with SessionLocal() as s:
        try:
            u = s.get(User, read_access(token)); m = s.scalars(select(Membership).where(Membership.user_id == u.id)).first()
            c = s.get(Channel, channel_id)
            ok = bool(u and m and c and c.workspace_id == m.workspace_id)
        except Exception: ok = False
    if not ok: await ws.close(code=4401); return
    await ws.accept(); hub.rooms[channel_id].add(ws)
    try:
        while True: await ws.receive_text()  # clients receive only; sending goes through REST
    except WebSocketDisconnect: pass
    finally: hub.rooms[channel_id].discard(ws)

# ---------- NOTIFICATIONS ----------
@app.get("/api/v1/notifications")
def notifications(u: User = Depends(current_user), s: Session = Depends(db)):
    rows = s.scalars(select(Notification).where(Notification.user_id == u.id).order_by(Notification.id.desc()).limit(50)).all()
    return {"unread": sum(1 for r in rows if not r.read), "items": [{"id": r.id, "text": r.text, "read": r.read} for r in rows]}

@app.post("/api/v1/notifications/read-all")
def read_all(u: User = Depends(current_user), s: Session = Depends(db)):
    for r in s.scalars(select(Notification).where(Notification.user_id == u.id, Notification.read == False)): r.read = True  # noqa
    s.commit(); return {"ok": True}

# ---------- DASHBOARD (all numbers computed from real rows) ----------
def stats(s, ws, u):
    ts = s.scalars(select(Task).where(Task.workspace_id == ws)).all(); today = now()
    open_ = [t for t in ts if t.status not in ("Done", "Cancelled")]
    over = [t for t in open_ if t.due_date and t.due_date.replace(tzinfo=timezone.utc) < today]
    done = [t for t in ts if t.status == "Done"]
    dated = [t for t in done if t.due_date and t.completed_at]
    ontime = sum(1 for t in dated if t.completed_at.replace(tzinfo=timezone.utc) <= t.due_date.replace(tzinfo=timezone.utc) + timedelta(days=1))
    weeks = []
    for i in range(6, -1, -1):
        a, b = today - timedelta(weeks=i + 1), today - timedelta(weeks=i)
        weeks.append({"week": f"W{7 - i}", "count": sum(1 for t in done if t.completed_at and a < t.completed_at.replace(tzinfo=timezone.utc) <= b)})
    return {"active_projects": s.scalar(select(func.count()).select_from(Project).where(Project.workspace_id == ws, Project.status == "Active")),
            "tasks_completed": len(done), "overdue": len(over), "open": len(open_),
            "members": s.scalar(select(func.count()).select_from(Membership).where(Membership.workspace_id == ws)),
            "on_time_pct": round(100 * ontime / len(dated)) if dated else None, "weekly": weeks, "my_open": sum(1 for t in open_ if t.assignee_id == u.id)}

@app.get("/api/v1/dashboard")
def dashboard(u: User = Depends(current_user), m: Membership = Depends(membership), s: Session = Depends(db)):
    act = s.scalars(select(Activity).where(Activity.workspace_id == m.workspace_id).order_by(Activity.id.desc()).limit(8)).all()
    return {**stats(s, m.workspace_id, u), "activity": [{"text": a.text, "at": a.created_at.isoformat()} for a in act]}

# ---------- AI assistant: rule-based, computed from authorised data only. No LLM provider wired yet. ----------
@app.post("/api/v1/ai/ask")
def ai_ask(b: AskIn, u: User = Depends(current_user), m: Membership = Depends(membership), s: Session = Depends(db)):
    st = stats(s, m.workspace_id, u); q = b.question.lower()
    names, pn = lookups(s, m.workspace_id)
    ts = s.scalars(select(Task).where(Task.workspace_id == m.workspace_id)).all()
    if "overdue" in q:
        o = [t.title for t in ts if t.status not in ("Done", "Cancelled") and t.due_date and t.due_date.replace(tzinfo=timezone.utc) < now()]
        text = f"{len(o)} overdue task(s): " + (", ".join(o[:10]) if o else "none.")
    elif "priorit" in q:
        c = sorted([t for t in ts if t.status not in ("Done", "Cancelled") and t.due_date], key=lambda t: t.due_date)[:3]
        text = "Suggested focus (earliest deadlines first): " + ("; ".join(f"{t.title} ({t.due_date.date()})" for t in c) or "no dated open tasks.")
    elif not any(k in q for k in ("summar", "status", "progress", "how many", "overview", "report")):
        text = "I can only answer from your workspace data. Try: 'summary', 'overdue tasks', or 'what should I prioritise?'"
    else:
        text = (f"{st['open']} open and {st['tasks_completed']} completed tasks across {st['active_projects']} active project(s); "
                f"{st['overdue']} overdue; {st['my_open']} open assigned to you.")
    return {"answer": text, "kind": "suggestion", "note": "Generated from your workspace data. Suggestions only; nothing was changed."}

# ---------- health, static frontend, custom 404 ----------
@app.get("/api/health")
def health(): return {"status": "ok"}

@app.exception_handler(404)
async def nf(request: Request, exc):
    if request.url.path.startswith("/api/"): return JSONResponse({"detail": getattr(exc, "detail", "Not found")}, 404)
    p = os.path.join(FRONTEND, "404.html")
    return FileResponse(p, status_code=404) if os.path.exists(p) else JSONResponse({"detail": "Not found"}, 404)

from . import extras  # noqa: E402  (registers extra models + routes)
app.include_router(extras.router)
Base.metadata.create_all(engine)  # NOTE: use Alembic migrations in production

if os.path.isdir(FRONTEND): app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="web")
