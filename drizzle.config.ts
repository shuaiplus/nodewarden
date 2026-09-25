import { defineConfig } from 'drizzle-kit';

// `out` doubles as wrangler's `migrations_dir`; wrangler discovers the
// drizzle-kit v1 nested layout through `migrations_pattern` in wrangler.toml.
export default defineConfig({
  dialect: 'sqlite',
  driver: 'd1-http',
  schema: './src/db/schema.ts',
  out: './migrations',
  dbCredentials: {
    accountId: process.env.CLOUDFLARE_ACCOUNT_ID ?? '',
    databaseId: process.env.CLOUDFLARE_DATABASE_ID ?? '',
    token: process.env.CLOUDFLARE_D1_TOKEN ?? '',
  },
});
