# Demo Video Script (viva backup)

Record this in about 5 minutes, in case the internet fails during your viva. Don't show `.env` or any password on screen.

**Before recording:** start everything with `.\scripts\start-all.ps1`, sign in, and use a clean window.

| Time | Show | Say |
|---|---|---|
| 0:00 | Project title | "This is a Hybrid WAF that combines attack signatures with Isolation Forest anomaly detection." |
| 0:20 | `http://localhost:3000` showing the refusal | "The website refuses direct visitors, so traffic can't skip the firewall." |
| 0:40 | `http://localhost:8000` with a normal search | "Through the WAF on port 8000, normal visitors use the site as usual." |
| 1:00 | Add `?q=' OR '1'='1` to the address | "This SQL injection is blocked before it reaches the website." |
| 1:20 | **Incidents** page and the row's details | "The incident is saved in PostgreSQL with its rule, location and evidence." |
| 1:50 | **Attack simulator**: run Evasion attempts | "Double encoding and SQL comments are decoded first, so these tricks are caught as well." |
| 2:20 | Simulator: run ML anomaly, then **ML anomalies** page | "These contain no attack keywords. ML flags them as evidence, without blocking them on its own." |
| 3:00 | Simulator: run Rate limit burst, then **IP management** | "Too many requests return 429, and repeated abuse earns a temporary ban." |
| 3:30 | **Settings**: switch to Monitor, save, then back to Block | "Monitor mode records without blocking, which helps us check false positives." |
| 3:50 | **Audit log** | "Every admin action is recorded with who did it and when." |
| 4:05 | **System health**, then the theme toggle | "Health checks are live, and the dashboard has dark and light modes." |
| 4:25 | `docs/evidence/evaluation.md` | Read your measured detection rate, false-positive rate and latency. |
| 4:50 | Limitations section of the report | "No WAF catches every attack. Our data is simulated, so we report these limits openly." |

Each member should present and explain their own part, as the CCP requires.
