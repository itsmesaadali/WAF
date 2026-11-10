import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import { createApp } from "./app.js";

const here = path.dirname(fileURLToPath(import.meta.url));
// Local development reads the project .env. Hosting platforms set real variables instead.
dotenv.config({ path: path.join(here, "..", "..", ".env"), quiet: true });

const host = process.env.SITE_HOST || "127.0.0.1";
const port = Number(process.env.PORT || process.env.SITE_PORT || 3000);
const app = createApp({ secret: process.env.WAF_SHARED_SECRET });

app.listen(port, host, () => {
  console.log(`Protected site listening on http://${host}:${port} (WAF traffic only)`);
});
