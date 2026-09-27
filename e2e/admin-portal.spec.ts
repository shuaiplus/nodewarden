import { test, expect, type Page } from '@playwright/test';
import { globSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';

const origin = process.env.E2E_ORIGIN;
const localOrigin = (() => {
  try { const url = new URL(origin ?? ''); return url.protocol === 'http:' && url.hostname === 'localhost'; }
  catch { return false; }
})();
const mailRoot = process.env.E2E_MAIL_ROOT || tmpdir();
let configuredAdmins = process.env.ADMIN_EMAILS ?? '';
try { configuredAdmins ||= readFileSync('.dev.vars', 'utf8').match(/^ADMIN_EMAILS\s*=\s*["']?([^\r\n"']+)/m)?.[1] ?? ''; } catch { /* Optional local configuration. */ }
const email = configuredAdmins.split(',')[0]?.trim().split(':')[0];

async function signIn(page: Page) {
  const started = Date.now();
  await page.goto(`${origin}/admin/login`);
  await page.getByLabel('Email', { exact: true }).fill(email);
  await page.getByRole('button', { name: 'Send sign-in link' }).click();
  await expect(page.getByText(/Open it in this browser/)).toBeVisible();
  let link = '';
  await expect.poll(() => {
    // Miniflare versions use either files/email-text or email/email-text.
    for (const path of globSync(`${mailRoot}/miniflare-*/**/email-text/**/*.txt`)) {
      try {
        if (!statSync(path).isFile() || statSync(path).mtimeMs < started) continue;
        const candidate = readFileSync(path, 'utf8').match(/http:\/\/localhost(?::\d+)?\/admin\/login\/confirm\?token=[A-Za-z0-9_-]{43}/)?.[0];
        if (candidate && new URL(candidate).origin === origin) { link = candidate; break; }
      } catch { /* A different local simulator may be shutting down. */ }
    }
    return link;
  }, { timeout: 15_000 }).not.toBe('');
  for (let visit = 0; visit < 2; visit++) {
    expect((await page.goto(link))?.status()).toBe(200);
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    expect((await page.context().cookies()).some((cookie) => cookie.name === '__Host-nw_admin')).toBe(false);
  }
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Administration', exact: true })).toBeVisible();
  expect((await page.context().cookies()).find((cookie) => cookie.name === '__Host-nw_admin')).toMatchObject({ secure: true, httpOnly: true, sameSite: 'Strict', path: '/' });
}

test('administrator sign-in isolates the portal from same-origin scripts, popups and frames', async ({ page, context }) => {
  test.skip(!localOrigin || !email, 'Requires local Wrangler with E2E_ORIGIN=http://localhost:<port> and ADMIN_EMAILS.');
  // A blank same-origin document with no CSP of its own stands in for a hostile same-origin script. The
  // Worker's only other pages (the connectors) forbid frames themselves, which would hide whether the
  // portal refuses to be framed; only this URL is fulfilled locally, every portal request is real.
  const app = await context.newPage();
  const probe = `${origin}/portal-isolation-probe`;
  await app.route(probe, (route) => route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>probe</title>' }));
  await app.goto(probe);
  await signIn(page);
  // Portal CSP blocks its own fetches before HTTP; exercise a real same-origin page instead.
  expect(await app.evaluate(async () => (await fetch('/admin')).status)).toBe(403);
  const popupPromise = app.waitForEvent('popup');
  await app.evaluate(() => { window.open('/admin'); });
  const popup = await popupPromise;
  await expect(popup.getByRole('heading', { name: 'Administration', exact: true })).toBeVisible();
  expect(await popup.evaluate(() => window.opener === null)).toBe(true);
  await popup.close();

  const iframeResponse = app.waitForResponse((response) => new URL(response.url()).pathname === '/admin');
  await app.evaluate(() => {
    const frame = document.createElement('iframe');
    frame.id = 'portal-isolation-frame'; frame.src = '/admin'; document.body.append(frame);
  });
  const denied = await iframeResponse;
  expect(denied.status()).toBe(403);
  expect(denied.headers()['x-frame-options']).toBe('DENY');
  expect(denied.headers()['content-security-policy']).toContain("frame-ancestors 'none'");
  await expect.poll(() => app.locator('#portal-isolation-frame').evaluate((frame: HTMLIFrameElement) => frame.contentDocument === null)).toBe(true);

  await page.getByRole('link', { name: 'Users', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Users', exact: true })).toBeVisible();
  const session = (await context.cookies()).find((cookie) => cookie.name === '__Host-nw_admin')!;
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByText('You have signed out.')).toBeVisible();
  expect((await context.cookies()).some((cookie) => cookie.name === '__Host-nw_admin')).toBe(false);
  await context.addCookies([session]);
  await page.goto(`${origin}/admin`);
  await expect(page.getByRole('heading', { name: 'Administrator sign-in', exact: true })).toBeVisible();
});

test('administrator deletes a disposable vault user through the confirmation form', async ({ page }) => {
  const targetEmail = process.env.E2E_DELETE_USER_EMAIL;
  test.skip(!localOrigin || !email || !targetEmail, 'Requires local Wrangler, ADMIN_EMAILS and a disposable E2E_DELETE_USER_EMAIL account.');
  await signIn(page);
  await page.goto(`${origin}/admin/users?email=${encodeURIComponent(targetEmail!)}`);
  const target = page.getByRole('link', { name: targetEmail!, exact: true });
  const viewPath = await target.getAttribute('href');
  await target.click();
  await page.getByLabel(`Type ${targetEmail} to confirm deletion`).fill(targetEmail!);
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page).toHaveURL(`${origin}/admin/users?m=deleted`);
  expect((await page.goto(`${origin}${viewPath}`))?.status()).toBe(404);
});

test('administrator disables and enables a vault account through the forms', async ({ page }) => {
  const targetEmail = process.env.E2E_STATUS_USER_EMAIL;
  test.skip(!localOrigin || !email || !targetEmail, 'Requires local Wrangler, ADMIN_EMAILS and a disposable E2E_STATUS_USER_EMAIL account.');
  await signIn(page);
  await page.goto(`${origin}/admin/users?email=${encodeURIComponent(targetEmail!)}`);
  await page.getByRole('link', { name: targetEmail!, exact: true }).click();
  await page.getByRole('button', { name: 'Disable user', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Enable user', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Enable user', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Disable user', exact: true })).toBeVisible();
  // Reuse this sign-in so the complete portal suite stays within its three-link issue budget.
  const resetEmail = process.env.E2E_RESET_USER_EMAIL;
  if (resetEmail) {
    await page.goto(`${origin}/admin/users?email=${encodeURIComponent(resetEmail)}`);
    await page.getByRole('link', { name: resetEmail, exact: true }).click();
    await page.getByLabel(`Type ${resetEmail} to remove two-step login`).fill(resetEmail);
    await page.getByRole('button', { name: 'Remove two-step login', exact: true }).click();
    await expect(page).toHaveURL(/m=two-factor-reset/);
    await expect(page.getByRole('button', { name: 'Remove two-step login', exact: true })).toHaveCount(0);
  }
});
