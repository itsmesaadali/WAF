# Hybrid Web Application Firewall

A firewall that sits in front of a website. It checks every request for SQL injection and XSS with attack signatures and machine learning, blocks attackers, and shows everything on an admin dashboard.

Information Security semester project, Riphah International University.
By **Saad Ali (56673)** and **Abrar Ali (55843)**. Instructor: Dr. Jawaid Iqbal.

> **For authorized use only.** Only protect or test websites you own or have permission to test. Attacking other people's sites is a crime under PECA 2016.

## Contents

1. [What it does](#what-it-does)
2. [How it works](#how-it-works)
3. [What you need to install](#what-you-need-to-install)
4. [Setup, step by step](#setup-step-by-step)
5. [Start the project](#start-the-project)
6. [Try it out](#try-it-out)
7. [Chrome extension](#chrome-extension)
8. [Run the tests](#run-the-tests)
9. [Stopping and starting again](#stopping-and-starting-again)
10. [Problems and fixes](#problems-and-fixes)
11. [Setup on macOS or Linux](#setup-on-macos-or-linux)
12. [Project layout](#project-layout)
13. [More guides](#more-guides)

## What it does

| Feature | How it works |
|---|---|
| Reverse proxy | Every request passes through the WAF first, and the website refuses anyone who tries to skip it |
| Signature detection | 26 rules find SQL injection and XSS, even when they're encoded or disguised |
| ML anomaly detection | An Isolation Forest model flags requests that look unusual |
| Rate limiting and bans | Stops floods, and bans an address for 15 minutes after 5 attacks |
| Incident logging | Saves every attack in PostgreSQL, with passwords and secrets removed |
| Admin security | Argon2 password hashes, signed login tokens, lockout after failed logins, and an audit log |
| Dashboard | Live traffic, incidents, IP bans, ML model, system health, CSV export, and dark and light themes |
| Attack simulator | Sends safe test attacks through the WAF with one click |
| Attack lab | Type any attack, disguise it, and see exactly how the WAF decodes and catches it. Nothing is sent anywhere |
| Block and Monitor modes | Block attacks, or only record them while you check for false alarms |
| Chrome extension | **WAF Link Guard** warns you about dangerous links and grades a site's security headers |

## How it works

```text
 Visitor ──► WAF (port 8000) ──► Website (port 3000)
               │
               ├─ checks signatures and the ML score
               ├─ blocks attacks with a 403 page
               └─ saves logs ──► Neon PostgreSQL ◄── Dashboard (port 3001)
```

| Part | Folder | Built with |
|---|---|---|
| WAF and admin API | `waf-backend/` | Python, FastAPI, scikit-learn |
| Protected test website | `protected-site/` | Node.js, Express |
| Admin dashboard | `dashboard/` | Next.js, TypeScript, Tailwind CSS, shadcn/ui |
| Database | `prisma/` | PostgreSQL on Neon, Prisma migrations |
| Chrome extension | `browser-extension/` | JavaScript, Manifest V3 |

## What you need to install

Install these once. The commands below are for Windows 10 or 11, in **PowerShell**.

| Tool | Version | Check it with | Get it |
|---|---|---|---|
| Git | any | `git --version` | `winget install Git.Git` or [git-scm.com](https://git-scm.com/downloads) |
| Python | 3.11 or newer | `py --version` | `winget install Python.Python.3.13` or [python.org](https://www.python.org/downloads/) |
| Node.js | 20.9 or newer (22 LTS recommended) | `node --version` | `winget install OpenJS.NodeJS.LTS` or [nodejs.org](https://nodejs.org/) |
| pnpm | 9 or newer | `pnpm --version` | `npm install -g pnpm` (after Node.js) |
| Neon account | free plan | | [neon.tech](https://neon.tech) |
| Google Chrome or Edge | any | | Only for the extension |

**Python on Windows:** when the installer asks, tick **"Add python.exe to PATH"** and keep **"py launcher"** ticked.

**After installing**, close PowerShell and open it again, so the new commands are found. Then run the "Check it with" commands. Each one should print a version number.

## Setup, step by step

You only do this once.

### Step 1: Download the code

```bash
git clone https://github.com/<owner>/<repo>.git
```

```bash
cd <repo>
```

Use the repository's real address from its GitHub page (green **Code** button). Every command after this runs **from this project folder**.

### Step 2: Create a free database on Neon

Each person needs their own database. Don't share one database or its password.

1. Sign up at [neon.tech](https://neon.tech) and create a project. Pick the region closest to you (for Pakistan, **Singapore**).
2. On the project dashboard, click **Connect**.
3. Copy two connection strings:
   - **Pooled:** with **Connection pooling** turned on. The host name contains `-pooler`.
   - **Direct:** with **Connection pooling** turned off.

Both look like `postgresql://user:password@host/neondb?sslmode=require`. Keep them private, because they contain your database password.

### Step 3: Allow PowerShell scripts

Windows blocks scripts by default. This allows them for the current PowerShell window only:

```bash
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Run it again whenever you open a new PowerShell window to run a `.ps1` script.

### Step 4: Create your settings file

```bash
.\scripts\setup.ps1
```

On the first run, it creates a file called `.env` with new random secrets, then stops with a message asking for the database.

Open `.env` in any editor (for example `notepad .env`) and fill in:

```env
DATABASE_URL=<your pooled connection string>
DATABASE_URL_UNPOOLED=<your direct connection string>
```

Save the file. Leave everything else as it is.

### Step 5: Install everything

Run the same script again:

```bash
.\scripts\setup.ps1
```

This time it does everything for you. It takes about 5 minutes:

1. Creates a Python virtual environment in `waf-backend\.venv` and installs the Python packages.
2. Installs the Node packages for the database tools, the website and the dashboard.
3. Creates the database tables in Neon.
4. Trains the ML model.
5. Creates `dashboard\.env.local`, which tells the dashboard where the WAF is.

It ends with **"Setup finished"**. If it stops with an error, see [Problems and fixes](#problems-and-fixes).

### Step 6: Find your admin password

Your admin password was generated for you. Open `.env` and look for:

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<random text>
```

That's your dashboard login. You can change it later in the dashboard's **Settings** page.

## Start the project

```bash
.\scripts\start-all.ps1
```

Three new windows open: the website, the WAF and the dashboard. **Keep them open** while you use the project. The dashboard takes about 20 seconds to be ready the first time.

| Address | What it is |
|---|---|
| http://localhost:8000 | The shop **through the WAF**. Always use this one |
| http://localhost:3001 | The admin dashboard |
| http://localhost:3000 | The shop directly. It should say **"Direct access is not allowed"**, which proves nobody can skip the WAF |

Open http://localhost:3001 and sign in with `admin` and the password from `.env`.

## Try it out

### 1. Watch the WAF block an attack

1. Open http://localhost:8000 and search for `book`. It works normally.
2. Search for `' OR '1'='1`. You get a **403 Blocked** page.
3. In the dashboard, open **Incidents**. The attack is there, with the rule that caught it.

### 2. Attack lab

1. In the dashboard sidebar, open **Attack lab**.
2. Pick a payload from the library, or type `<script>alert(1)</script>`.
3. Press the **Disguise it** buttons (URL encoding, Base64, comments, invisible characters). They stack, and the counter shows how many disguises the WAF still caught.
4. Look at the tabs: how the payload was decoded, which rules matched, and the ML score.
5. Try the safe examples, like `O'Brien`. They should be allowed.

Nothing in the Attack lab is sent to the website or saved in the logs.

### 3. Attack simulator

Open **Attack simulator**, run a scenario, then watch **Live traffic** and **Incidents** fill up.

### 4. Other pages

| Page | What to look at |
|---|---|
| Overview | Requests, attacks and blocks over time |
| Live traffic | Every request, allowed or blocked |
| IP management | Ban or unban addresses, and the allowlist |
| ML anomalies | Unusual requests the model flagged, its threshold, and retraining it |
| System health | Whether the WAF, website and database are working |
| Settings | Block or Monitor mode, limits, and changing your password |
| Audit log | Every admin action |

### Careful: you can ban yourself

After 5 attacks from one address, the WAF bans it for 15 minutes. While testing, that address is your own computer, so every page shows **"Your address is temporarily blocked."**

To fix it, open the dashboard, go to **IP management**, and lift the ban on `127.0.0.1`. To stop it happening while you practise, add `127.0.0.1` to the **allowlist** on the same page. Remove it again before a demo, so the ban can be shown.

## Chrome extension

**WAF Link Guard** uses the same rules as the WAF, inside your browser.

**Install it:**
1. Open `chrome://extensions` (or `edge://extensions` in Edge).
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and choose the `browser-extension` folder inside this project.
4. Click the puzzle-piece icon and pin **WAF Link Guard**.

**Try it:**
1. With the project running, open http://localhost:8000/link-guard-demo.html.
2. Dangerous links get a red dashed outline, and the toolbar badge shows how many there are.
3. Click one. The extension warns you first. If you click **Open anyway**, the WAF blocks it with a 403. That's two layers of protection.
4. Click the extension icon to see the page report, the security header grade, and the **Check text** box.
5. Right-click any link and choose **Check this link**.

More details are in [browser-extension/README.md](browser-extension/README.md).

## Run the tests

| What | Command | Time |
|---|---|---|
| Fast tests (no database needed) | `.\scripts\test.ps1 -UnitOnly` | About 30 seconds |
| All tests | `.\scripts\test.ps1` | About 6 minutes |

The full run starts its own copies of the WAF and website on ports 8100 and 3100, and uses a separate `waf_test` area in the database, so your real logs aren't touched. See [docs/TESTING.md](docs/TESTING.md) for the attack suite and evaluation.

## Stopping and starting again

- **To stop:** close the three windows that `start-all.ps1` opened, or press `Ctrl+C` in each.
- **Next time:** you don't need setup again. Open PowerShell in the project folder and run:
  ```bash
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  ```
  ```bash
  .\scripts\start-all.ps1
  ```
- **After pulling new code from GitHub:** run `.\scripts\setup.ps1` again. It keeps your `.env` and only installs what changed.

## Problems and fixes

| Problem | Fix |
|---|---|
| `running scripts is disabled on this system` | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then try again |
| `py` or `pnpm` is not recognized | Install it (see [What you need to install](#what-you-need-to-install)), then close and reopen PowerShell |
| Setup stops at "Open .env, set DATABASE_URL…" | That's expected on the first run. Do [Step 4](#step-4-create-your-settings-file) |
| `Database migration failed` or `P1001: Can't reach database` | Check both URLs in `.env` are complete and end with `?sslmode=require`. A free Neon database sleeps when idle, so wait a few seconds and try again |
| `Python package install failed` | Check `py --version` is 3.11 or newer, then delete the `waf-backend\.venv` folder and rerun setup |
| A port is already in use | Something else is using port 8000, 3000 or 3001. Close it, or restart the computer |
| Dashboard says it can't reach the WAF | The WAF window isn't running or showed an error. Start it, then refresh the dashboard |
| Sign-in fails with the right password | After 5 wrong tries the account locks for 15 minutes. To reset the password, run `cd waf-backend` then `.venv\Scripts\python.exe -m app.cli reset-password --username admin` |
| "Your address is temporarily blocked" | You banned yourself. See [Careful: you can ban yourself](#careful-you-can-ban-yourself) |
| The shop shows 502 | The website window isn't running. Start the project again |
| The extension shows nothing | Reload the page. Pages opened before you installed it aren't scanned |

## Setup on macOS or Linux

The scripts are for Windows PowerShell. On macOS or Linux, run the same steps by hand from the project folder, after installing Python 3.11+, Node.js 20.9+ and pnpm:

```bash
python3 scripts/setup-env.py
```

Now put your two Neon URLs in `.env` ([Step 2](#step-2-create-a-free-database-on-neon) and [Step 4](#step-4-create-your-settings-file)), then:

```bash
python3 -m venv waf-backend/.venv && waf-backend/.venv/bin/pip install -r waf-backend/requirements-dev.txt
```

```bash
pnpm install && pnpm --dir protected-site install --ignore-workspace && pnpm --dir dashboard install --ignore-workspace
```

```bash
pnpm db:deploy
```

```bash
(cd waf-backend && .venv/bin/python -m app.ml.train)
```

```bash
echo "WAF_API_URL=http://127.0.0.1:8000" > dashboard/.env.local
```

To start, open three terminals in the project folder and run one command in each:

```bash
cd protected-site && pnpm start
```

```bash
cd waf-backend && .venv/bin/python -m app.main
```

```bash
cd dashboard && pnpm dev --port 3001
```

## Project layout

```text
waf-backend/        Python WAF and admin API
  app/detection/    Signatures, decoding and matching
  app/ml/           Isolation Forest features and training
  app/proxy/        The reverse proxy
  app/api/          Admin API used by the dashboard
protected-site/     Express test website (a small shop)
dashboard/          Next.js admin console
browser-extension/  WAF Link Guard Chrome extension
prisma/             Database tables and migrations
tests/              Unit, integration, attack and evaluation tests
scripts/            Setup, start and test scripts
docs/               Guides and saved test evidence
render.yaml         Hosting settings for Render
.env.example        Template for your private .env file
```

## Keep your secrets safe

- `.env` holds your database password and secrets. It's listed in `.gitignore`, so Git never uploads it. **Never** commit it, paste it in chat, or share a screenshot of it.
- Each person makes their own `.env` with `setup.ps1`. Don't copy someone else's.
- If a secret leaks, change it: reset the database password in Neon, and generate new secrets by deleting their values in `.env` and running `.\scripts\setup.ps1`.

## More guides

| Guide | Read it to |
|---|---|
| [Admin guide](docs/ADMIN_GUIDE.md) | Use every dashboard page and respond to incidents |
| [Testing](docs/TESTING.md) | Run all tests, the attack suite and the evaluation |
| [Deployment](docs/DEPLOYMENT.md) | Put it online with Render, Vercel and Neon |
| [Architecture](docs/ARCHITECTURE.md) | See the design, risks and limitations |
| [Demo video script](docs/DEMO_VIDEO_SCRIPT.md) | Record a demo |
| [Chrome extension](browser-extension/README.md) | Install and demo WAF Link Guard |

Saved test results are in [docs/evidence](docs/evidence).

No firewall stops every attack. The limitations are explained in [ARCHITECTURE.md](docs/ARCHITECTURE.md).
