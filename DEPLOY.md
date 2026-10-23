# Deploying SyncSpace (Vercel frontend + Render API + Neon Postgres)

1. **Database (Neon):** create a project at neon.tech and copy the connection string.
2. **API (Render):** New > Web Service from your GitHub repo.
   - Root directory: `backend` | Build: `pip install -r requirements.txt`
   - Start: `uvicorn app.main:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips="*"`
   - Env vars: `APP_ENV=production`, `JWT_SECRET_KEY=<long random string>`, `DATABASE_URL=<Neon string>`
   - Check `https://<service>.onrender.com/api/health` returns `{"status":"ok"}`.
3. **Frontend (Vercel):** import the repo, set Root Directory to `frontend`, Framework Preset "Other", no build command.
   Edit `frontend/vercel.json` and replace `YOUR-BACKEND.onrender.com` with your Render host before pushing.
4. Open your Vercel URL, create an account.

Notes: chat refreshes every 5 s on Vercel (no WebSockets through the proxy). Uploaded files live on Render's temporary disk and disappear on redeploy until S3-style storage is added. Render's free tier sleeps, so the first request can take ~30 s.

## Netlify instead of Vercel
Steps 1-2 are the same (Neon + Render). Then edit `frontend/netlify.toml` (replace `YOUR-BACKEND.onrender.com`), push, and in Netlify choose Add new site > Import from Git, Base directory `frontend`, no build command, Publish directory `.`.
