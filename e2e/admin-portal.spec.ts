import { test, expect } from '@playwright/test';
import { globSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';

const origin = process.env.E2E_ORIGIN;
let configuredAdmins = process.env.ADMIN_EMAILS ?? '';
try { configuredAdmins ||= readFileSync('.dev.vars', 'utf8').match(/^ADMIN_EMAILS\s*=\s*["']?([^\r\n"']+)/m)?.[1] ?? ''; } catch { /* Optional local configuration. */ }
const email = configuredAdmins.split(',')[0]?.trim().split(':')[0];

test('administrator confirms a local email link, rejects same-origin script access and signs out', async ({ page }) => {
  test.skip(origin !== 'http://localhost:8787' || !email, 'Requires local Wrangler simulation with E2E_ORIGIN=http://localhost:8787 and ADMIN_EMAILS.');
  const started = Date.now();
  await page.goto(`${origin}/admin/login`);
  await page.getByLabel('Email', { exact: true }).fill(email);
  await page.getByRole('button', { name: 'Send sign-in link' }).click();
  await expect(page.getByText(/Open it in this browser/)).toBeVisible();
  let link = '';
  await expect.poll(() => {
    const paths = globSync(`${tmpdir()}/miniflare-*/files/email-text/**/*`).filter((path) => statSync(path).isFile() && statSync(path).mtimeMs >= started).sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
    for (const path of paths) {
      const candidate = readFileSync(path, 'utf8').match(/http:\/\/localhost:8787\/admin\/login\/confirm\?token=[A-Za-z0-9_-]{43}/)?.[0];
      if (candidate) { link = candidate; break; }
    }
    return link;
  }).not.toBe('');
  await page.goto(link);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Administration', exact: true })).toBeVisible();
  expect(await page.evaluate(async () => (await fetch('/admin')).status)).toBe(403);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByText('You have signed out.')).toBeVisible();
});
