# Administrator Guide

## Sign in

Open the dashboard and sign in as `admin`. On your PC, the first password is `ADMIN_PASSWORD` in your `.env` file. After 5 wrong attempts, the account locks for 15 minutes.

Change the password from **Settings**. This signs out every session.

## Pages

| Page | Use it to |
|---|---|
| **Overview** | See totals, traffic over time, incident types, top sources and latest incidents |
| **Live traffic** | Watch each request, its result and timing. Refreshes about every 3 seconds. |
| **Incidents** | Filter, review and export security events as CSV. Click a row for details. |
| **ML anomalies** | See flagged requests, scores and the model's status, and retrain it |
| **IP management** | Ban or unban addresses |
| **Attack lab** | Check any payload against the real engine, try disguises, and see the decoding steps, matching rules and ML score. Nothing is sent or logged. |
| **Attack simulator** | Run fixed test requests against your configured website |
| **Settings** | Change the mode, limits, allowlist, ML options and your password |
| **System health** | Check the website, database, ML model and log writer |
| **Audit log** | See who signed in or changed something |

The header always shows the environment (LOCAL or LIVE), the protected website and the current mode.

## Block and Monitor modes

- **Block** stops attacks. Use this normally.
- **Monitor** records what would have been blocked, but lets everything through. Use it briefly to check false positives on a new site. **It doesn't protect the website.**

## Handle an incident

1. Open it on **Incidents**, and read the rule, location and matched text.
2. Set its status: **Reviewed** if it's real, or **False positive** if it's legitimate.
3. For repeat attackers, use **Ban this IP**.

Matched text comes from attackers, so treat it as untrusted. The dashboard shows it as plain text, and exports neutralize spreadsheet formulas.

## Reduce false positives

1. Mark the incident as a false positive, and note its rule.
2. Add trusted addresses to the allowlist. They skip bans and rate limits, but signatures still apply.
3. To relax or remove a rule, edit `waf-backend/app/detection/signatures.py`, add the case to `tests/unit/test_signatures.py`, then rerun the tests.

## Retrain the ML model

Retrain when normal traffic changes, for example when you protect a new website.

- **Retrain (simulated)** uses only the generated traffic.
- **Retrain (with real traffic)** adds requests the WAF allowed. It needs at least 200.

Only retrain when you're confident the recent traffic is normal, because attackers can try to teach a model that their behaviour is normal. Flagged, blocked and simulated requests are excluded to limit this.

Keep **Block flagged requests** off unless you've measured false positives on your own traffic.

## Manage admin accounts

Run these from `waf-backend`. Passwords are typed privately.

```powershell
.venv\Scripts\python.exe -m app.cli create-admin --username sara
.venv\Scripts\python.exe -m app.cli reset-password --username admin
.venv\Scripts\python.exe -m app.cli delete-admin --username sara
```

## Security and privacy rules

- Never share `.env`, database URLs, or the shared secret.
- Logs store IP addresses and request details, so only give access to authorized admins.
- Request bodies aren't stored. Passwords and tokens are removed from logged queries and evidence.
- Request logs and incidents are deleted after `LOG_RETENTION_DAYS` (30 by default).
- Test only systems you own or have written permission to test.

## If something goes wrong

| What you see | What it means | What to do |
|---|---|---|
| Logs waiting keeps growing | Database is slow or down | Check Neon. Traffic keeps flowing, and logs retry. |
| Logs lost is above 0 | Queue filled, or shutdown during an outage | Note the time in your records, and fix the database |
| ML model: Not loaded | Model file missing or tampered with | Retrain from **ML anomalies**. Signatures still protect the site. |
| Protected website: Unreachable | Website down or wrong address | Check `UPSTREAM_URL`. Visitors see a 502 page. |
| Inspection errors above 0 | A bug in the inspection code | Requests are blocked while `FAIL_MODE=closed`. Check server logs. |
