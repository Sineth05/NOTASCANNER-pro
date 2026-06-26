# NOTA Scanner Server Backend

This is the central authentication, HWID lock, and scan reporting server for NOTA Scanner.

## Features
- User & Admin Roles with SQLite fallback or PostgreSQL support.
- Hardware ID (HWID) binding and verification to prevent account sharing.
- Scan logs reporting and centralized retrieval dashboard.

## Deployment to Railway.app

### Method 1: Deploy via GitHub (Recommended)
1. Initialize a new git repository in this `server` directory or your project root:
   ```bash
   git init
   git add .
   git commit -m "Initialize NOTA Auth Server"
   ```
2. Create a repository on GitHub and push your commits.
3. Go to [Railway.app](https://railway.app) and log in.
4. Click **New Project** -> **Deploy from GitHub repo** and select your repository.
5. Railway will automatically detect the Node.js project.
6. (Optional but recommended for production database persistence):
   * Click **New** -> **Database** -> **Add PostgreSQL** in your Railway project dashboard.
   * Railway will automatically inject the `DATABASE_URL` environment variable into your server, switching the backend from SQLite to PostgreSQL automatically.

### Environment Variables
If you need to configure custom settings, add these variables in your Railway Project **Variables** tab:
- `PORT` (default: 5000)
- `JWT_SECRET` (custom encryption key string for JWT validation)
- `DATABASE_URL` (injected automatically when PostgreSQL is added)
