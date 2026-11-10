# Self-Deployment Guide

You do these steps yourself. Plan names and prices change, so check each provider's current page.

**What goes where**

| Part | Host | Why |
|---|---|---|
| Dashboard | Vercel | Built for Next.js |
| WAF | Render (Docker web service) | Runs a persistent Python process |
| Test website (optional) | Render | Only needed if you protect the included test site |
| Database | Neon | Already created in Singapore |

Render's Singapore region matches your Neon region, which keeps database calls short.

## Before you start

1. **Change your Neon password.** The current one was shared in chat. In the Neon console, reset the database password, then update `DATABASE_URL` and `DATABASE_URL_UNPOOLED` in your local `.env`.
2. **Create a live database branch.** In Neon, open **Branches**, create one named `live`, and copy its pooled and direct URLs. This keeps test data out of your live results.
3. **Push your code** to a private GitHub repository. Confirm `.env` isn't included:
   ```bash
   git status --ignored
   ```
4. **Generate secrets for live.** Don't reuse your local ones. Run this three times, and save each value in a password manager:
   ```bash
   py -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

## Step 1: Create the live tables

In PowerShell, from the project folder, using the `live` branch's **direct** URL:

```powershell
$env:DATABASE_URL_UNPOOLED = "<live branch direct URL>"
pnpm db:deploy
Remove-Item Env:DATABASE_URL_UNPOOLED
```

## Step 2: Deploy to Render

1. In Render, choose **New > Blueprint** and connect your repository. It reads `render.yaml`.
2. Enter the values it asks for:

   | Variable | Service | Value |
   |---|---|---|
   | `DATABASE_URL` | hybrid-waf | `live` branch **pooled** URL |
   | `UPSTREAM_URL` | hybrid-waf | Website to protect (see the next section) |
   | `WAF_SHARED_SECRET` | both | First generated secret. It must match on both services. |
   | `ADMIN_PASSWORD` | hybrid-waf | A strong password, at least 12 characters |

   Render generates `JWT_SECRET` and `MODEL_SIGNING_KEY` itself.
3. When the deploy finishes, open `https://<your-waf>.onrender.com/__waf/ping`. It should show `{"status":"ok"}`.

If you protect only `itsmesaad.me`, delete the `hybrid-waf-test-site` block from `render.yaml` first.

**Plan choice:** `render.yaml` uses an always-on paid plan for the WAF. A sleeping free WAF takes time to wake, and takes your site down with it if your domain points to it.

## Step 3: Choose what the WAF protects

### Option A: the included test site
Set `UPSTREAM_URL` to the test site's Render URL. Direct visits to that URL must show "Direct access is not allowed".

### Option B: safe demo with `itsmesaad.me` (recommended)
Your main site keeps working normally, and you show the WAF on a subdomain.

1. Find your site's `.vercel.app` address in the Vercel project's **Domains** page.
2. Set `UPSTREAM_URL` to `https://<your-project>.vercel.app`.
3. In Render, open the WAF service, choose **Settings > Custom Domains**, and add `waf.itsmesaad.me`.
4. In Namecheap, add the CNAME record Render shows you for `waf`.
5. Open `https://waf.itsmesaad.me`.

**Limit:** people who visit `itsmesaad.me` directly skip the WAF. Say this in your report and viva. If Vercel Deployment Protection is on, the WAF can't fetch the `.vercel.app` address until it's turned off or a bypass is set up.

### Option C: full protection for `itsmesaad.me`
Only do this after Option B works. If the WAF goes down, your whole site goes down too.

1. Add `WAF_SHARED_SECRET` to the site's Vercel environment variables.
2. Add a `proxy.ts` file to the site, next to `app` (use `middleware.ts` on Next.js 15 or older):
   ```ts
   import { NextResponse, type NextRequest } from "next/server"

   export function proxy(request: NextRequest) {
     if (request.headers.get("x-waf-secret") !== process.env.WAF_SHARED_SECRET) {
       return new NextResponse("Direct access is not allowed.", { status: 403 })
     }
     return NextResponse.next()
   }
   ```
3. Deploy the site, then confirm direct `.vercel.app` visits show 403 and `waf.itsmesaad.me` still works.
4. In Render, add `itsmesaad.me` as a custom domain. In Namecheap, point the domain to Render as instructed. Remove the domain from the Vercel project.

To undo it, point Namecheap back to Vercel and remove `proxy.ts`. DNS changes can take time to spread.

## Step 4: Deploy the dashboard to Vercel

1. In Vercel, choose **Add New > Project** and import your repository.
2. Set **Root Directory** to `dashboard`.
3. Add the environment variable `WAF_API_URL` with your WAF's `https://` address, without a trailing slash.
4. Deploy, open the URL, and sign in with `admin` and your `ADMIN_PASSWORD`.
5. Check the header shows **LIVE** and the correct website.

## Step 5: Run the live checks

### Check the visitor IP first
This setting decides who gets banned, so it must be right.

1. Find your public IP by searching "what is my IP".
2. Run the attack suite below. It prints `Your IP as seen by the WAF`.
3. If it doesn't match your IP, change `TRUST_PROXY_HOPS` in Render. Try `2`, then redeploy and check again.

**Don't leave this wrong.** If it shows a Render address, one ban could block every visitor.

### Run the attack suite
Check your host's security-testing rules first, and only test sites you own.

```powershell
$env:WAF_ADMIN_USER = "admin"
$env:WAF_ADMIN_PASSWORD = Read-Host "Live admin password"
waf-backend\.venv\Scripts\python.exe tests\attacks\attack_suite.py --base-url https://waf.itsmesaad.me --read-only --output docs\evidence\attack-suite-live.json
Remove-Item Env:WAF_ADMIN_USER, Env:WAF_ADMIN_PASSWORD
```

Use your WAF's own address in place of `waf.itsmesaad.me`. Add `--direct-url <website address>` if the website has the secret check.

## Live checklist

- [ ] Neon password changed, with live secrets different from local ones
- [ ] `/__waf/ping` returns `{"status":"ok"}`
- [ ] Dashboard signs in, and shows **LIVE** and the correct website
- [ ] WAF sees your real public IP
- [ ] Attack suite passes, and attacks appear on the Incidents page
- [ ] Direct access to the website returns 403 (test site, or Option C)
- [ ] System health shows all parts healthy
- [ ] Default password changed from **Settings** if it was ever shared
- [ ] Results and screenshots saved in `docs/evidence`

## Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| Dashboard says it can't reach the WAF | Wrong `WAF_API_URL` | Use the full `https://` address, then redeploy |
| Every website request shows 502 | Wrong `UPSTREAM_URL`, or the site is down | Open that address directly and correct it |
| Website shows 403 through the WAF | Secrets don't match | Set the same `WAF_SHARED_SECRET` on both sides |
| You banned yourself | Too many test attacks | Unban the IP on **IP management**, then allowlist it |
| Sign-in fails with the right password | No admin was created, or it's locked | Wait 15 minutes, or reset it with `py -m app.cli reset-password --username admin` |
| Everyone appears with one IP | `TRUST_PROXY_HOPS` is wrong | Follow "Check the visitor IP first" |
| Requests are slow after idle | Free hosting sleeping, or Neon waking | Use always-on hosting, and open the site before a demo |
