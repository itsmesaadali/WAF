import path from "node:path";
import { config as loadEnv } from "dotenv";
import { defineConfig } from "prisma/config";

// Local development reads .env. CI and hosting set real environment variables instead.
loadEnv({ path: path.join(import.meta.dirname, ".env"), quiet: true });

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: { path: "prisma/migrations" },
  datasource: {
    // Migrations need the direct connection: Neon's pooled URL doesn't support them.
    url: process.env.DATABASE_URL_UNPOOLED ?? "",
  },
});
