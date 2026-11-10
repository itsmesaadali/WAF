# Architecture and Security Design

## Request flow

```text
Visitor
  │
  ▼
Hybrid WAF (FastAPI)
  1. Banned IP?              yes → 403
  2. Over rate limit?        yes → 429
  3. Body too large?         yes → 413
  4. Signatures match?       yes → 403 and incident
  5. ML score unusual?       yes → flag and incident (blocks only if enabled)
  6. Forward with the secret header
  │
  ▼
Protected website (refuses requests without the secret)

Every request ──► background log writer ──► Neon PostgreSQL ◄── WAF admin API
                                                                      ▲
Admin's browser ──► Next.js dashboard (server-side bridge) ───────────┘
```

Monitor mode runs the same checks, but records and forwards instead of blocking.

## Folders

| Folder | Contents |
|---|---|
| `waf-backend/app/proxy` | Reverse proxy and request decisions |
| `waf-backend/app/detection` | Normalizer, signatures, inspection engine, log redaction |
| `waf-backend/app/ml` | Features, simulated traffic, training, signed model files |
| `waf-backend/app/security` | Client IP handling, rate tracking, passwords and tokens |
| `waf-backend/app/services` | Background log writer, ban list, runtime settings |
| `waf-backend/app/api` | Protected admin APIs and the simulator |
| `protected-site` | Express test website with bypass protection |
| `dashboard` | Next.js admin console |
| `prisma` | Database design and migrations |
| `tests` | Unit, integration, attack and evaluation tests |

## Why these choices

| Decision | Reason | Trade-off |
|---|---|---|
| Signatures and ML together | Signatures catch known attacks and explain why. ML notices unusual behaviour. | ML adds latency and false alarms |
| ML flags but doesn't block by default | The proposal treats ML as supporting evidence | Unusual requests still reach the website until an admin reacts |
| Decode before matching | Stops common encoding tricks | Bounded decoding can't cover every trick |
| Features contain no attack keywords | ML stays independent of the signatures | It sees shape and behaviour only, not meaning |
| Prisma for tables, SQLAlchemy in Python | Prisma's official clients don't include Python, and a test confirms the two match | Two descriptions of the tables to keep aligned |
| Background log writing | Visitors don't wait for the database | Queued logs can be lost if the process crashes |
| In-memory rate limits | Very fast, with no database call per request | Counts reset on restart, and it suits one WAF instance |
| Dashboard bridge with httpOnly cookie | The login token never reaches browser JavaScript | One extra network hop |
| WAF logs bodies as evidence snippets only | Limits personal data stored | Less detail when investigating |

## How the proposal's principles are applied

| Principle | Where |
|---|---|
| Defense in depth | Signatures, ML, rate limits, bans, and escaping in the website itself |
| Complete mediation | Every non-admin path goes through the same pipeline, and the website refuses anything else |
| Fail-safe defaults | Oversized or compressed bodies are refused, `FAIL_MODE=closed` blocks on inspection errors, and the website won't start without a secret |
| Least privilege | Docker containers run without root, and the simulator can't choose targets or payloads |
| Confidentiality | Hashed passwords, redacted logs, secrets outside the code, login needed for all logs |
| Integrity | Signed tokens, signed ML model files, audit log of admin actions |
| Availability | Rate limits, bounded inspection, and traffic continues during database outages |

## Risk treatment

Risks are from the Task 1 proposal.

| Threat | Initial risk | Controls | Remaining risk |
|---|---|---|---|
| SQL injection | High | Signatures, decoding, website input handling | Medium: new techniques can pass (see `docs/evidence/evaluation.md`) |
| Cross-site scripting | High | Signatures, decoding, output escaping in the test site | Medium: same reason |
| Abnormal API traffic | High | Rate limits, bans, ML flags | Medium: slow or distributed traffic can stay under limits |
| WAF bypass or evasion | High | Secret header, localhost binding, decoding, compressed-body refusal | Medium: depends on the website enforcing the secret |
| WAF misconfiguration or failure | High | Validated settings, health page, fail-closed mode, tests | Medium: the WAF is a single point of failure |
| False-positive IP blocking | Medium | Temporary bans, allowlist, Monitor mode, unban, review status | Low to medium |
| Unauthorized access to logs | Medium | Argon2 hashes, token checks, lockout, audit log | Low |
| ML misclassification | Medium | Flag-only default, measured false positives, retraining | Low to medium |

Remaining risk levels are the project's own judgement, based on test results.

## Known limitations

- **Detection isn't complete.** New attack techniques can pass, and some test payloads were missed.
- **Simulated data.** Model training and evaluation use simulated traffic, so real-world results may differ.
- **Single instance.** Rate limits and ban lookups live in one process. Several WAF copies would need shared storage.
- **No WebSocket support.** The proxy handles normal HTTP requests only.
- **Request size.** Bodies are held in memory up to `MAX_BODY_BYTES` and aren't suitable for large uploads.
- **Polling, not streaming.** The dashboard refreshes every few seconds, so "live" means a short delay.
- **Secret header depends on the website.** A hosted site must add the check, or its direct address stays open.
- **Bypass from a stolen secret.** Anyone with the shared secret can reach the website directly, so rotate it if exposed.
- **Response content isn't inspected.** The WAF checks requests, not what the website returns.

## Future work

- Shared rate limits with Redis, for more than one WAF instance
- WebSocket support and streaming inspection for large uploads
- Larger signature coverage based on the full OWASP Core Rule Set
- Evaluation with an independent dataset and real, consented traffic
- Two-factor login for administrators
