# The Archive — Music School LMS

> A full-stack Learning Management System built for The Archive Music School (Est. 1952). Features course management, live classes, Razorpay payments, certificate generation, analytics, and more — styled in a vintage academic aesthetic.

---

## Table of Contents

- [Tech Stack](#tech-stack)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Local Development Setup](#local-development-setup)
- [Environment Variables](#environment-variables)
- [Third-Party Configuration](#third-party-configuration)
- [Deployment Guide](#deployment-guide)
  - [Option A — Railway (Recommended)](#option-a--railway-recommended)
  - [Option B — Render](#option-b--render)
  - [Option C — Ubuntu VPS (DigitalOcean / AWS EC2 / Hetzner)](#option-c--ubuntu-vps-digitalocean--aws-ec2--hetzner)
  - [Option D — AWS Elastic Beanstalk](#option-d--aws-elastic-beanstalk)
- [Post-Deployment Checklist](#post-deployment-checklist)
- [Default Credentials](#default-credentials)
- [Project Structure](#project-structure)
- [API Reference](#api-reference)

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Runtime** | Node.js 18+ |
| **Framework** | Express.js 4 |
| **Database** | SQLite via better-sqlite3 |
| **Auth** | JWT (jsonwebtoken) + bcryptjs |
| **Payments** | Razorpay |
| **File Uploads** | Multer |
| **Frontend** | Vanilla HTML + CSS + JS (no framework) |
| **Fonts** | Google Fonts — Newsreader + Work Sans |
| **Charts** | Pure SVG/Canvas (no external libraries) |

---

## Features

- **28 pages** — Auth, dashboards, courses, gradebook, quiz, messaging, analytics, payments, certificates, live classes, search, resources, and more
- **100+ REST API endpoints** across 27 route files
- **28 SQLite tables** — fully relational schema
- **Razorpay payment gateway** with order creation and HMAC verification
- **SVG certificate generation** — vintage diploma design, downloadable
- **Practice log** with GitHub-style heatmap
- **Global search** across courses, sheet music, students, resources
- **Email automation** with 4 seeded HTML templates
- **Role-based access** — Student, Instructor, Admin
- **Admin panel** — S3, SMTP, Razorpay configuration with step-by-step guides

---

## Prerequisites

| Requirement | Minimum Version | Check |
|---|---|---|
| Node.js | 18.x | `node --version` |
| npm | 9.x | `npm --version` |
| Git | 2.x | `git --version` |

> **Note:** better-sqlite3 compiles native binaries. On Linux servers you need `build-essential` and `python3`. See the VPS guide below.

---

## Local Development Setup

### Step 1 — Clone the repository

```bash
git clone https://github.com/techinfinitydevelopers/Niladri.git
cd Niladri
```

### Step 2 — Install dependencies

```bash
npm install
```

### Step 3 — Configure environment variables

```bash
cp .env.example .env   # or manually create .env (see Environment Variables section)
```

Edit `.env` with your values (see [Environment Variables](#environment-variables) below).

### Step 4 — Start the server

```bash
npm start
```

The server starts on **http://localhost:3001**

> The SQLite database (`data/archive.db`) and all required directories are created automatically on first run. Demo seed data (2 users, 4 courses, 10 quotes, 3 masterclasses) is inserted if the database is empty.

### Step 5 — Open the app

Navigate to **http://localhost:3001** and log in with the [default credentials](#default-credentials).

---

## Environment Variables

Create a `.env` file in the project root with the following variables:

```env
# ── Server ──────────────────────────────────────────────
PORT=3001
UPLOAD_DIR=./data/uploads

# ── Auth ────────────────────────────────────────────────
# Change this to a long random string in production
JWT_SECRET=replace_with_a_very_long_random_secret_string
JWT_EXPIRES_IN=7d

# ── Razorpay ────────────────────────────────────────────
# Get these from https://dashboard.razorpay.com/app/keys
RAZORPAY_KEY_ID=rzp_test_xxxxxxxxxxxx
RAZORPAY_KEY_SECRET=xxxxxxxxxxxxxxxxxxxxxxxx
RAZORPAY_WEBHOOK_SECRET=your_webhook_secret

# ── GitHub (optional — for CI/CD) ───────────────────────
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
GITHUB_REPO=techinfinitydevelopers/Niladri
```

> **Production tip:** Never commit `.env` to git. It is already listed in `.gitignore`.

---

## Third-Party Configuration

All third-party services can be configured via the **Admin Panel** at `/admin-panel.html` after logging in as an instructor or admin.

### Razorpay Setup

1. Sign up at [razorpay.com](https://razorpay.com)
2. Complete KYC verification (required for live payments)
3. Go to **Dashboard → Settings → API Keys**
4. Click **Generate Test Key** — copy the **Key ID** and **Key Secret**
5. Add them to your `.env` as `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET`
6. For webhooks: **Dashboard → Settings → Webhooks → Add New**
   - URL: `https://yourdomain.com/api/payments/webhook`
   - Events: `payment.captured`, `payment.failed`
   - Copy the webhook secret to `RAZORPAY_WEBHOOK_SECRET`
7. When ready for live payments: generate **Live Keys** and update `.env`

### AWS S3 Setup (for media storage)

1. Create an AWS account at [aws.amazon.com](https://aws.amazon.com)
2. Go to **S3 → Create Bucket** (e.g., `archive-lms-media`)
3. Uncheck **Block all public access** for public media files
4. Add this CORS configuration to the bucket:
   ```json
   [
     {
       "AllowedHeaders": ["*"],
       "AllowedMethods": ["GET", "PUT", "POST", "DELETE"],
       "AllowedOrigins": ["*"],
       "ExposeHeaders": []
     }
   ]
   ```
5. Go to **IAM → Users → Add User** → attach policy `AmazonS3FullAccess`
6. Download the credentials CSV — copy **Access Key ID** and **Secret Access Key**
7. Enter these in **Admin Panel → S3 Configuration**

### SMTP Setup (for email automation)

**Option 1 — Gmail:**
1. Enable 2FA on your Google account
2. Go to **myaccount.google.com → Security → App Passwords**
3. Generate a password for "Mail"
4. SMTP Host: `smtp.gmail.com`, Port: `587`, Encryption: TLS

**Option 2 — SendGrid:**
1. Create an account at [sendgrid.com](https://sendgrid.com)
2. Go to **Settings → API Keys → Create API Key**
3. SMTP Host: `smtp.sendgrid.net`, Port: `587`
4. Username: `apikey`, Password: your API key

Configure in **Admin Panel → SMTP Configuration → Save**.

---

## Deployment Guide

---

### Option A — Railway (Recommended)

Railway is the fastest way to deploy — no server management required.

#### Step 1 — Push your code to GitHub

Ensure your latest code is on the `main` branch of your GitHub repository.

#### Step 2 — Create a Railway project

1. Go to [railway.app](https://railway.app) and sign in with GitHub
2. Click **New Project → Deploy from GitHub repo**
3. Select `techinfinitydevelopers/Niladri`
4. Railway auto-detects Node.js and runs `npm start`

#### Step 3 — Add environment variables

1. In your Railway project, click the service → **Variables**
2. Click **Raw Editor** and paste your complete `.env` contents
3. Change `PORT` to `${{PORT}}` (Railway injects this automatically)

#### Step 4 — Add a persistent volume for SQLite

1. In your Railway project, click **New → Volume**
2. Mount path: `/app/data`
3. This ensures your database survives redeploys

#### Step 5 — Deploy

Railway deploys automatically on every push to `main`. Your app will be live at a `*.railway.app` URL.

#### Step 6 — Add a custom domain (optional)

1. Railway project → **Settings → Domains → Add Custom Domain**
2. Add your domain and follow the DNS instructions (CNAME record)

---

### Option B — Render

#### Step 1 — Create a Web Service

1. Go to [render.com](https://render.com) → **New → Web Service**
2. Connect your GitHub repo `techinfinitydevelopers/Niladri`
3. Settings:
   - **Environment:** Node
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
   - **Instance Type:** Starter ($7/month) or free tier

#### Step 2 — Add environment variables

Go to **Environment → Add Environment Variable** and add all variables from your `.env`.

#### Step 3 — Add a persistent disk

1. Go to **Disks → Add Disk**
2. Mount Path: `/opt/render/project/src/data`
3. Size: 1 GB (minimum)

> Update your `.env` on Render: set `UPLOAD_DIR=/opt/render/project/src/data/uploads`

#### Step 4 — Deploy

Click **Deploy** — Render builds and starts your service. Your app is live at `*.onrender.com`.

---

### Option C — Ubuntu VPS (DigitalOcean / AWS EC2 / Hetzner)

This guide assumes a fresh Ubuntu 22.04 server.

#### Step 1 — Connect to your server

```bash
ssh root@your-server-ip
```

#### Step 2 — Install system dependencies

```bash
# Update system
apt update && apt upgrade -y

# Install Node.js 20 (via NodeSource)
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs

# Install build tools (required for better-sqlite3)
apt install -y build-essential python3 git

# Install PM2 (process manager)
npm install -g pm2

# Install Nginx (reverse proxy)
apt install -y nginx

# Verify
node --version   # should be v20.x
npm --version
```

#### Step 3 — Create a non-root user (recommended)

```bash
adduser deploy
usermod -aG sudo deploy
su - deploy
```

#### Step 4 — Clone the repository

```bash
cd /home/deploy
git clone https://github.com/techinfinitydevelopers/Niladri.git archive-lms
cd archive-lms
```

#### Step 5 — Install dependencies

```bash
npm install --production
```

#### Step 6 — Create the environment file

```bash
nano .env
```

Paste your complete `.env` contents. Set `PORT=3001`.

Save with `Ctrl+X → Y → Enter`.

#### Step 7 — Create required directories

```bash
mkdir -p data/uploads data/certificates
```

#### Step 8 — Start with PM2

```bash
# Start the app
pm2 start server/index.js --name "archive-lms"

# Save PM2 config so it restarts on server reboot
pm2 save
pm2 startup   # follow the printed instructions to enable on boot
```

Verify it's running:
```bash
pm2 status
pm2 logs archive-lms --lines 20
```

#### Step 9 — Configure Nginx as a reverse proxy

```bash
sudo nano /etc/nginx/sites-available/archive-lms
```

Paste this config (replace `yourdomain.com`):

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    # Max upload size (for sheet music, recordings etc.)
    client_max_body_size 100M;

    location / {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 300s;
    }

    # Serve uploaded files directly via Nginx (faster)
    location /uploads/ {
        alias /home/deploy/archive-lms/data/uploads/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/archive-lms /etc/nginx/sites-enabled/
sudo nginx -t        # test config
sudo systemctl restart nginx
```

#### Step 10 — Enable HTTPS with Let's Encrypt (SSL)

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

Follow the prompts. Certbot auto-renews SSL certificates. Your app is now live at `https://yourdomain.com`.

#### Step 11 — Set up auto-deploy on git push (optional)

```bash
# Create a deploy script
nano /home/deploy/deploy.sh
```

```bash
#!/bin/bash
cd /home/deploy/archive-lms
git pull origin main
npm install --production
pm2 restart archive-lms
echo "Deploy complete at $(date)"
```

```bash
chmod +x /home/deploy/deploy.sh
```

You can trigger this manually with `./deploy.sh` or hook it to GitHub Actions (see below).

#### Step 12 — GitHub Actions CI/CD (optional)

Create `.github/workflows/deploy.yml` in your repo:

```yaml
name: Deploy to VPS

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy via SSH
        uses: appleboy/ssh-action@v1.0.0
        with:
          host: ${{ secrets.VPS_HOST }}
          username: ${{ secrets.VPS_USER }}
          key: ${{ secrets.VPS_SSH_KEY }}
          script: /home/deploy/deploy.sh
```

Add `VPS_HOST`, `VPS_USER`, and `VPS_SSH_KEY` to your GitHub repo secrets.

---

### Option D — AWS Elastic Beanstalk

#### Step 1 — Install the EB CLI

```bash
pip install awsebcli
```

#### Step 2 — Initialise Elastic Beanstalk

```bash
cd archive-lms
eb init archive-lms --platform node.js-20 --region ap-south-1
```

#### Step 3 — Create a Procfile

```bash
echo "web: npm start" > Procfile
```

#### Step 4 — Create the environment

```bash
eb create archive-lms-prod --instance-type t3.small
```

#### Step 5 — Set environment variables

```bash
eb setenv \
  JWT_SECRET=your_secret \
  PORT=8080 \
  RAZORPAY_KEY_ID=rzp_live_xxx \
  RAZORPAY_KEY_SECRET=xxx \
  UPLOAD_DIR=/tmp/uploads
```

#### Step 6 — Deploy

```bash
eb deploy
```

> **Note:** Elastic Beanstalk uses ephemeral storage. For persistent SQLite + uploads, mount an EFS volume or migrate to RDS (PostgreSQL) for production.

---

## Post-Deployment Checklist

After deploying, complete these steps:

- [ ] **Log in** with default credentials and change the instructor password immediately
- [ ] **Configure SMTP** in Admin Panel → test by sending yourself an email
- [ ] **Configure Razorpay** in Admin Panel → run a test ₹1 payment
- [ ] **Configure S3** (if using cloud storage) in Admin Panel → test connection
- [ ] **Create an admin user** via `/api/roles/users` PUT endpoint (change instructor role to `admin`)
- [ ] **Set JWT_SECRET** to a strong random value (at least 64 characters) — generate one with:
  ```bash
  node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
  ```
- [ ] **Verify HTTPS** is working (padlock in browser)
- [ ] **Test payment flow** end-to-end with a Razorpay test card
- [ ] **Upload your first course** via Course Manager
- [ ] **Review file upload limits** — Nginx is configured for 100MB; adjust `client_max_body_size` as needed

---

## Default Credentials

> ⚠️ Change these immediately after first login in production.

| Role | Email | Password |
|---|---|---|
| **Instructor** | `instructor@archive.edu` | `password123` |
| **Student** | `student@archive.edu` | `password123` |

---

## Project Structure

```
archive-lms/
├── .env                          # Environment variables (never commit)
├── .gitignore
├── package.json
├── README.md
│
├── server/
│   ├── index.js                  # Express entry point
│   ├── db.js                     # SQLite schema + seed data
│   ├── middleware/
│   │   ├── auth.js               # JWT verification
│   │   └── role.js               # Role-based access guard
│   └── routes/                   # 27 route files
│       ├── auth.routes.js
│       ├── courses.routes.js
│       ├── enrollments.routes.js
│       ├── lessons.routes.js
│       ├── chapters.routes.js
│       ├── assignments.routes.js
│       ├── quiz.routes.js
│       ├── submissions.routes.js
│       ├── sheetmusic.routes.js
│       ├── recordings.routes.js
│       ├── masterclasses.routes.js
│       ├── live-classes.routes.js
│       ├── announcements.routes.js
│       ├── resources.routes.js
│       ├── messages.routes.js
│       ├── notifications.routes.js
│       ├── profile.routes.js
│       ├── analytics.routes.js
│       ├── practice-log.routes.js
│       ├── calendar.routes.js
│       ├── payments.routes.js
│       ├── certificates.routes.js
│       ├── search.routes.js
│       ├── email.routes.js
│       ├── roles.routes.js
│       ├── quotes.routes.js
│       └── admin.routes.js
│
├── public/                       # 28 HTML pages + assets
│   ├── index.html                # Auth (login/register/forgot)
│   ├── student-dashboard.html
│   ├── instructor-dashboard.html
│   ├── student-course-catalog.html
│   ├── student-course-detail.html
│   ├── course-manager.html
│   ├── student-lessons.html
│   ├── gradebook.html
│   ├── quiz-builder.html
│   ├── quiz-take.html
│   ├── student-profile.html
│   ├── student-notifications.html
│   ├── student-messaging.html
│   ├── analytics-student.html
│   ├── analytics-instructor.html
│   ├── student-practice-log.html
│   ├── student-calendar.html
│   ├── student-sheet-music.html
│   ├── studio.html
│   ├── student-archive.html
│   ├── student-payments.html
│   ├── student-certificates.html
│   ├── student-live-classes.html
│   ├── student-search.html
│   ├── student-announcements.html
│   ├── student-resources.html
│   ├── email-automation.html
│   ├── admin-panel.html
│   └── assets/
│       ├── css/archive.css       # Shared design system
│       └── js/
│           ├── api.js            # Fetch wrapper + auth header
│           └── auth-guard.js     # Redirect if not logged in
│
└── data/                         # Auto-created, gitignored
    ├── archive.db                # SQLite database
    ├── uploads/                  # User-uploaded files
    └── certificates/             # Generated SVG certificates
```

---

## API Reference

All protected endpoints require the header:
```
Authorization: Bearer <jwt_token>
```

Obtain a token via `POST /api/auth/login`.

| Group | Base Path | Key Endpoints |
|---|---|---|
| **Auth** | `/api/auth` | login, register, verify-otp, forgot-password, reset-password, /me |
| **Courses** | `/api/courses` | CRUD, chapters with nested lessons |
| **Enrollments** | `/api/enrollments` | enroll, unenroll, progress |
| **Lessons** | `/api/lessons` | list, complete |
| **Chapters** | `/api/chapters` | CRUD |
| **Assignments** | `/api/assignments` | CRUD by course |
| **Quizzes** | `/api/quizzes` | CRUD, start/submit attempts, auto-grade |
| **Submissions** | `/api/submissions` | submit, grade |
| **Sheet Music** | `/api/sheet-music` | list, upload, download |
| **Recordings** | `/api/recordings` | CRUD, audio upload |
| **Masterclasses** | `/api/masterclasses` | list, register |
| **Live Sessions** | `/api/live-sessions` | CRUD, join/leave, status |
| **Announcements** | `/api/announcements` | CRUD, pin, email broadcast |
| **Resources** | `/api/resources` | CRUD, download with counter |
| **Messages** | `/api/messages` | threads, reply, read |
| **Notifications** | `/api/notifications` | list, mark read, unread count |
| **Profile** | `/api/profile` | get/update, avatar upload, password change |
| **Analytics** | `/api/analytics` | student stats, instructor stats, course stats |
| **Practice Log** | `/api/practice-log` | CRUD, heatmap, stats |
| **Calendar** | `/api/calendar` | events CRUD, masterclass overlay |
| **Payments** | `/api/payments` | create-order, verify, history |
| **Certificates** | `/api/certificates` | list, generate, download SVG |
| **Search** | `/api/search` | cross-entity search with type filter |
| **Email** | `/api/email` | templates CRUD, send, logs |
| **Roles** | `/api/roles` | user role management, TA assignment |
| **Admin** | `/api/admin` | S3/SMTP/Razorpay config, test connections |
| **Quotes** | `/api/quotes` | random musical quote |

---

## Troubleshooting

**`better-sqlite3` build fails on Linux:**
```bash
apt install -y build-essential python3
npm rebuild better-sqlite3
```

**Port already in use:**
```bash
lsof -ti:3001 | xargs kill -9
npm start
```

**Database locked error:**
```bash
# Stop all server instances then restart
pm2 restart archive-lms
```

**Uploads not persisting on Render/Railway:**
Ensure you have mounted a persistent disk/volume at the `data/` directory path.

**Razorpay payment returns 403:**
Verify `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET` match the mode (test/live) selected in Admin Panel.

---

## License

MIT © 2026 Tech Infinity Developers / The Archive Music School
