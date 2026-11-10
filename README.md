# Hybrid Web Application Firewall

A reverse-proxy firewall that combines attack signatures with machine-learning anomaly detection, and a dashboard to monitor and manage it.

Information Security semester project, Riphah International University. By Saad Ali (56673) and Abrar Ali (55843).

**For authorized use only.** Only protect or test websites you own or have permission to test.

## What it does

| Feature | How it works |
|---|---|
| Reverse proxy | Every request passes through the WAF, and the website refuses direct visitors |
| Signature detection | Finds SQL injection and XSS, including encoded and hidden versions |
| ML anomaly detection | Isolation Forest scores unusual requests as supporting evidence |
| Rate limiting and bans | Stops floods, and temporarily bans repeat attackers |
| Incident logging | Saves events permanently in PostgreSQL, with secrets removed |
| Admin security | Argon2 password hashes, signed tokens, lockout and an audit log |
| Dashboard | Dark and light themes, live traffic, incidents, IP management, ML, health, CSV export and an attack simulator |
| Block and Monitor modes | Block attacks, or only record them while checking for false positives |
| Attack lab | Try any payload and its disguises against the real engine, and see each decoding step, the matching rules and the ML score. Nothing is sent or logged |
| Chrome extension | **WAF Link Guard** uses the same rules in the browser to warn about dangerous links and grade a site's security headers |

## Technology

- **WAF:** Python, FastAPI, scikit-learn
- **Protected website:** Node.js, Express
- **Dashboard:** Next.js, TypeScript, Tailwind CSS, shadcn/ui
- **Database:** PostgreSQL (Neon), with Prisma migrations and SQLAlchemy in the WAF

## Run it on Windows

**You need:** Python 3.11 or newer (`py`), Node.js 20 or newer, pnpm, and a Neon database.

### 1. First-time setup

In PowerShell, from this folder:

```powershell
.\scripts\setup.ps1
```

The first run creates `.env` with random secrets, then stops if the database isn't set. Add your Neon URLs to `DATABASE_URL` and `DATABASE_URL_UNPOOLED`, then run it again.

If PowerShell blocks the script, allow it for this window, then rerun:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### 2. Start everything

```powershell
.\scripts\start-all.ps1
```

| Address | What it is |
|---|---|
| http://localhost:8000 | Website **through the WAF** (use this one) |
| http://localhost:3001 | Dashboard |
| http://localhost:3000 | Website directly, which must refuse you |

### 3. Sign in

Open the dashboard and sign in as `admin`. The password is `ADMIN_PASSWORD` in your `.env` file. Change it from **Settings**.

### 4. Try it

- Open **Attack lab**, pick a payload and press the **Disguise it** buttons to see whether the WAF still catches it.
- Open **Attack simulator** and run a scenario, then check **Incidents** and **Live traffic**.
- Install the Chrome extension and open http://localhost:8000/link-guard-demo.html. See [browser-extension/README.md](browser-extension/README.md).

## Protect a different website

Change one line in `.env`, then restart the WAF:

```env
UPSTREAM_URL=https://itsmesaad.me
```

Then visit the site at http://localhost:8000. This tests the WAF on your PC, so **real visitors aren't protected until you deploy it**. See [DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Guides

| Guide | Read it to |
|---|---|
| [Testing](docs/TESTING.md) | Run all tests, on local and hosted sites |
| [Deployment](docs/DEPLOYMENT.md) | Deploy it yourself, step by step |
| [Admin guide](docs/ADMIN_GUIDE.md) | Use the dashboard and respond to incidents |
| [Architecture](docs/ARCHITECTURE.md) | See the design, risk treatment and limitations |
| [Demo video script](docs/DEMO_VIDEO_SCRIPT.md) | Record your viva backup |
| [Chrome extension](browser-extension/README.md) | Install and demo WAF Link Guard |

Saved test results are in [docs/evidence](docs/evidence).

## Project layout

```text
waf-backend/      Python WAF and admin API
protected-site/   Express test website
dashboard/        Next.js admin console
browser-extension/ WAF Link Guard Chrome extension
prisma/           Database design and migrations
tests/            Unit, integration, attack and evaluation tests
scripts/          PowerShell setup, start and test commands
docs/             Guides and test evidence
render.yaml       Hosting blueprint for the WAF and test site
```

## Safety notes

- `.env` holds your secrets. It's excluded from Git, so never share or commit it.
- Five blocked requests from one IP trigger a temporary ban. If this happens to you, unban yourself on **IP management**.
- Monitor mode doesn't protect the website.
- No WAF stops every attack. See the limitations in [ARCHITECTURE.md](docs/ARCHITECTURE.md).
