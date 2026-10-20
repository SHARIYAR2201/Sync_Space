"""Comments + @mentions, file attachments (local adapter), direct messages, authorised search."""
import os, re, uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, String, ForeignKey, DateTime, Text, Integer, or_, and_
from sqlalchemy.orm import Session, Mapped, mapped_column
from .core import Base, User, Task, Project, Message, Channel, Membership, now
from .main import db, current_user, membership, lookups, notify, log_activity

router = APIRouter(prefix="/api/v1")
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
MAX_BYTES = int(os.getenv("MAX_UPLOAD_MB", "10")) * 1024 * 1024
ALLOWED = {".png": b"\x89PNG", ".jpg": b"\xff\xd8", ".jpeg": b"\xff\xd8", ".pdf": b"%PDF", ".txt": None, ".md": None, ".csv": None}

class Comment(Base):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Attachment(Base):
    __tablename__ = "attachments"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    filename: Mapped[str] = mapped_column(String(200))
    stored: Mapped[str] = mapped_column(String(80))
    size: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class DirectMessage(Base):
    __tablename__ = "direct_messages"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Body(BaseModel): body: str = Field(min_length=1, max_length=4000)

def task_in_ws(s, m, tid):
    t = s.get(Task, tid)
    if not t or t.workspace_id != m.workspace_id: raise HTTPException(404, "Task not found.")
    return t

# ---- comments ----
@router.get("/tasks/{tid}/comments")
def comments(tid: int, m: Membership = Depends(membership), s: Session = Depends(db)):
    task_in_ws(s, m, tid); names, _ = lookups(s, m.workspace_id)
    return [{"id": c.id, "author": names.get(c.user_id, "Former member"), "body": c.body, "at": c.created_at.isoformat()}
            for c in s.scalars(select(Comment).where(Comment.task_id == tid).order_by(Comment.id))]

@router.post("/tasks/{tid}/comments", status_code=201)
def add_comment(tid: int, b: Body, u: User = Depends(current_user), m: Membership = Depends(membership), s: Session = Depends(db)):
    t = task_in_ws(s, m, tid); c = Comment(task_id=tid, user_id=u.id, body=b.body.strip()); s.add(c)
    names, _ = lookups(s, m.workspace_id); targets = set()
    for tag in re.findall(r"@(\w+)", b.body):  # @firstname mentions, only workspace members
        targets |= {uid for uid, n in names.items() if n.lower().startswith(tag.lower()) and uid != u.id}
    if t.assignee_id and t.assignee_id != u.id: targets.add(t.assignee_id)
    for uid in targets: notify(s, uid, f"{u.name} commented on {t.title}")
    log_activity(s, m.workspace_id, f"{u.name} commented on {t.title}"); s.commit()
    return {"id": c.id, "author": u.name, "body": c.body, "at": c.created_at.isoformat()}

# ---- attachments (local disk adapter; swap for S3 later) ----
@router.post("/tasks/{tid}/attachments", status_code=201)
async def upload(tid: int, file: UploadFile = File(...), u: User = Depends(current_user),
                 m: Membership = Depends(membership), s: Session = Depends(db)):
    task_in_ws(s, m, tid)
    name = re.sub(r"[^\w.\- ]", "_", os.path.basename(file.filename or "file"))[:100]
    ext = os.path.splitext(name)[1].lower()
    if ext not in ALLOWED: raise HTTPException(415, f"File type not allowed. Allowed: {', '.join(sorted(ALLOWED))}")
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES: raise HTTPException(413, f"File is larger than {MAX_BYTES // 1048576} MB.")
    magic = ALLOWED[ext]
    if magic and not data.startswith(magic): raise HTTPException(415, "File contents do not match its extension.")
    os.makedirs(UPLOAD_DIR, exist_ok=True); stored = uuid.uuid4().hex + ext
    with open(os.path.join(UPLOAD_DIR, stored), "wb") as f: f.write(data)
    a = Attachment(workspace_id=m.workspace_id, task_id=tid, user_id=u.id, filename=name, stored=stored, size=len(data))
    s.add(a); s.commit(); return {"id": a.id, "filename": name, "size": a.size}

@router.get("/tasks/{tid}/attachments")
def list_files(tid: int, m: Membership = Depends(membership), s: Session = Depends(db)):
    task_in_ws(s, m, tid)
    return [{"id": a.id, "filename": a.filename, "size": a.size} for a in s.scalars(select(Attachment).where(Attachment.task_id == tid))]

@router.get("/attachments/{aid}")
def download(aid: int, m: Membership = Depends(membership), s: Session = Depends(db)):
    a = s.get(Attachment, aid)  # permission checked on every download
    if not a or a.workspace_id != m.workspace_id: raise HTTPException(404, "File not found.")
    return FileResponse(os.path.join(UPLOAD_DIR, a.stored), filename=a.filename, media_type="application/octet-stream")

# ---- direct messages ----
@router.get("/dm/{uid}")
def dm_history(uid: int, u: User = Depends(current_user), m: Membership = Depends(membership), s: Session = Depends(db)):
    q = select(DirectMessage).where(DirectMessage.workspace_id == m.workspace_id, or_(
        and_(DirectMessage.sender_id == u.id, DirectMessage.recipient_id == uid),
        and_(DirectMessage.sender_id == uid, DirectMessage.recipient_id == u.id))).order_by(DirectMessage.id.desc()).limit(100)
    return [{"id": d.id, "mine": d.sender_id == u.id, "body": d.body, "at": d.created_at.isoformat()} for d in list(s.scalars(q))[::-1]]

@router.post("/dm/{uid}", status_code=201)
def dm_send(uid: int, b: Body, u: User = Depends(current_user), m: Membership = Depends(membership), s: Session = Depends(db)):
    names, _ = lookups(s, m.workspace_id)
    if uid not in names or uid == u.id: raise HTTPException(404, "Recipient not found in this workspace.")
    d = DirectMessage(workspace_id=m.workspace_id, sender_id=u.id, recipient_id=uid, body=b.body.strip()); s.add(d)
    notify(s, uid, f"New message from {u.name}"); s.commit()
    return {"id": d.id, "mine": True, "body": d.body, "at": d.created_at.isoformat()}

# ---- search: only workspace-scoped rows are ever queried ----
@router.get("/search")
def search(q: str = Query(min_length=2, max_length=100), u: User = Depends(current_user),
           m: Membership = Depends(membership), s: Session = Depends(db)):
    like = "%" + q.replace("%", r"\%").replace("_", r"\_") + "%"; ws = m.workspace_id
    cids = select(Channel.id).where(Channel.workspace_id == ws)
    names, _ = lookups(s, ws)
    return {
        "projects": [{"id": p.id, "name": p.name} for p in s.scalars(select(Project).where(Project.workspace_id == ws, Project.name.ilike(like, escape="\\")).limit(10))],
        "tasks": [{"id": t.id, "title": t.title, "status": t.status} for t in s.scalars(select(Task).where(Task.workspace_id == ws, Task.title.ilike(like, escape="\\")).limit(10))],
        "messages": [{"id": x.id, "body": x.body[:120], "channel_id": x.channel_id} for x in s.scalars(select(Message).where(Message.channel_id.in_(cids), Message.body.ilike(like, escape="\\")).limit(10))],
        "members": [{"id": i, "name": n} for i, n in names.items() if q.lower() in n.lower()][:10],
    }
