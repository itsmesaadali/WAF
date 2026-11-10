# Hybrid WAF Dashboard

The admin console for the Hybrid WAF. See the main [README](../README.md) to run it, and [DEPLOYMENT](../docs/DEPLOYMENT.md) to host it on Vercel.

It reads only real data from the WAF, through a server-side bridge at `app/api/waf`. Set `WAF_API_URL` to the WAF's address.
