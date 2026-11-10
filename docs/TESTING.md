# Testing Guide

Run commands in PowerShell from the project folder.

## Which test does what

| Test | What it proves | Needs |
|---|---|---|
| Unit tests | Signatures, ML, IP handling, tokens and redaction work | Nothing running |
| Website tests | The test site refuses direct access | Nothing running |
| Extension tests | The Chrome extension gives the same answers as the WAF, and grades headers correctly | Nothing running |
| End-to-end tests | Real WAF, website and database work together | Database in `.env` |
| Attack suite | A running WAF blocks attacks and allows normal traffic | A running WAF |
| Dashboard check | Dashboard login and API protections work | All three apps running |
| Evaluation | Compares signatures alone with signatures plus ML | Database in `.env`; running apps for latency |

## Automated tests

```powershell
.\scripts\test.ps1 -UnitOnly
.\scripts\test.ps1
```

The full run takes several minutes, because it talks to Neon. It starts its own WAF and website on ports 8100 and 3100, and keeps its data in a separate `waf_test` database schema, so your real logs aren't affected.

## Test which setup?

The attack suite tests any setup. Only the addresses change.

| WAF runs on | Website | Set `UPSTREAM_URL` to | Run the suite with |
|---|---|---|---|
| Your PC | Local | `http://127.0.0.1:3000` | `--base-url http://127.0.0.1:8000 --direct-url http://127.0.0.1:3000` |
| Your PC | Hosted | `https://itsmesaad.me` | `--base-url http://127.0.0.1:8000 --read-only` |
| Deployed | Hosted | Site's `vercel.app` address | `--base-url https://your-waf-address --read-only` |
| Deployed | Local | Tunnel URL (see below) | `--base-url https://your-waf-address` |

After changing `UPSTREAM_URL` in `.env`, restart the WAF. The output prints which website is behind the WAF, so you can confirm you're testing the right one.

### Local website

```powershell
waf-backend\.venv\Scripts\python.exe tests\attacks\attack_suite.py --base-url http://127.0.0.1:8000 --direct-url http://127.0.0.1:3000 --output docs\evidence\attack-suite-local.json
```

### Hosted website

`--read-only` means only normal GET requests reach your site. Attacks stop at the WAF. Without `--direct-url`, this doesn't test direct access, and on the WAF-on-your-PC setup real visitors aren't protected.

```powershell
waf-backend\.venv\Scripts\python.exe tests\attacks\attack_suite.py --base-url http://127.0.0.1:8000 --read-only --output docs\evidence\attack-suite-hosted.json
```

### Deployed WAF with a local website

A deployed WAF can't reach `localhost` on your PC, so you need a tunnel, such as Cloudflare Tunnel or ngrok. Point the tunnel at port 3000, set `UPSTREAM_URL` on the WAF to the tunnel's URL, and keep your PC on. Only use this for testing.

## Manual checks

With everything running (`.\scripts\start-all.ps1`):

| Do this | Expected result |
|---|---|
| Open `http://localhost:3000` | "Direct access is not allowed" |
| Open `http://localhost:8000` | The shop's home page |
| Open `http://localhost:8000/products?q=book` | Search results |
| Open `http://localhost:8000/products?q=' OR '1'='1` | "Request blocked" page, and a new incident on the dashboard |
| Open `http://localhost:8000/products?q=<script>alert(1)</script>` | "Request blocked" page |
| Run each scenario on **Attack simulator** | Results appear on Traffic and Incidents |

**Avoid banning yourself:** five blocked requests from your own browser trigger a 15-minute ban. Unban yourself on **IP management**, or use the simulator, which uses reserved test addresses.

## Dashboard security check

```powershell
waf-backend\.venv\Scripts\python.exe tests\integration\check_dashboard_security.py
```

## Evaluation

```powershell
waf-backend\.venv\Scripts\python.exe tests\evaluation\run_evaluation.py --waf-url http://127.0.0.1:8000 --site-url http://127.0.0.1:3000
```

This writes `docs/evidence/evaluation.md` and `evaluation.json`. Rerun it after changing rules or the model, and use the new numbers in your report.

**In simple words:**
- **Detection rate:** the share of attack requests caught.
- **False-positive rate:** the share of normal requests wrongly flagged. Lower is better.
- **Latency:** the extra time the WAF adds to a request.

The test traffic is simulated and written by the project authors, so the report should describe these as results on this dataset, not a general guarantee.

## Evidence for your report

`docs/evidence` holds the saved results from these runs. Add dashboard screenshots there as well.
