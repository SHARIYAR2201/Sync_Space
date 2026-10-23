# SyncSpace

Team collaboration platform: FastAPI backend + the original single-page React frontend, now wired to a real database.

## Run locally (no paid services needed)
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000    # serves API and frontend
# open http://localhost:8000
python -m pytest -q                          # backend tests
```
Docker (from repo root): `docker build -f backend/Dockerfile -t syncspace . && docker run -p 8000:8000 syncspace`.
Config: see `backend/.env.example`. Default DB is SQLite; set `DATABASE_URL` for PostgreSQL. In production set `JWT_SECRET_KEY` (the app refuses to start without it).

## What works
Sign up / sign in / sign out, refresh-token rotation with reuse detection, password reset (single-use, 1h), profile edit, workspaces with Owner/Admin/Manager/Member roles, invitations (hashed, expiring, single-use), projects with progress computed from tasks, tasks (create, status change, assignee, priority, due date), Kanban and My Tasks views, channels with persisted messages and live WebSocket delivery, notifications (assignments), dashboard and analytics computed from real rows, task comments with @mention notifications, file attachments (type/size/magic-byte checks, permission-checked downloads, local disk adapter), direct messages, workspace-scoped search (projects, tasks, messages, members), rule-based AI assistant (suggestions from your own data), auth rate limiting, custom 404.
Cancelled tasks are excluded from project progress; archived projects are hidden from lists.

## Known limitations (not done yet)
No UI yet for comments, attachments, DMs or search (the API endpoints exist and are tested). Still missing: email sending (tokens are logged), Alembic migrations, Google OAuth, labels/subtasks, calendar view, drag-and-drop, Redis, LLM provider for AI, workspace switcher, Playwright/Vitest tests, S3 storage. CI runs backend tests only. The frontend loads React/Tailwind from CDNs.

## Email (invitations and password reset)
Copy `backend/.env.example` to `backend/.env` and fill in the SMTP settings (the Gmail example uses an App Password). Restart the server. If email is not configured, the app says so and gives the admin an invite link to send manually. Invited people open the link, sign in or create an account with the invited email address, and are added to the workspace.
