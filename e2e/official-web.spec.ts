import { test, expect } from '@playwright/test';

const workerOrigin = process.env.E2E_ORIGIN || 'http://127.0.0.1:8787';
const officialWebOrigin = process.env.OFFICIAL_WEB_ORIGIN || 'http://127.0.0.1:8080';

test.describe('official Bitwarden web against NodeWarden', () => {
  test('identity send-verification-email does not return an inline JWT', async ({ request }) => {
    const email = `official-${Date.now()}@example.com`;
    const start = await request.post(`${workerOrigin}/identity/accounts/register/send-verification-email`, {
      headers: { Origin: workerOrigin, 'Content-Type': 'application/json' },
      data: { email, name: 'Official', receiveMarketingEmails: false },
    });
    expect(start.ok(), await start.text()).toBeTruthy();
    const body = await start.json();
    expect(body).toBe('');
  });

  test('official web vault signup waits for the verification email', async ({ page, request }) => {
    const config = await request.get(`${officialWebOrigin}/api/config`, {
      headers: { 'Accept-Encoding': 'identity' },
    });
    expect(config.ok(), await config.text()).toBeTruthy();
    const payload = await config.json();
    expect(payload.object).toBe('config');
    expect(payload.environment?.api).toContain('/api');

    const email = `official-ui-${Date.now()}@example.com`;
    await page.goto(officialWebOrigin);
    await expect(page).toHaveTitle(/Bitwarden Web vault/i);
    await page.getByRole('link', { name: /create account/i }).click();
    await expect(page.getByRole('heading', { name: /create account/i })).toBeVisible();
    await page.getByLabel(/email address/i).fill(email);
    const nameField = page.getByLabel(/^name$/i);
    if (await nameField.count()) await nameField.fill('Official');
    const verify = page.waitForResponse(
      (response) => response.url().includes('/accounts/register/send-verification-email') && response.request().method() === 'POST'
    );
    await page.getByRole('button', { name: /^continue$/i }).click();
    const verifyResponse = await verify;
    expect(verifyResponse.ok()).toBeTruthy();
    expect(await verifyResponse.json()).toBe('');
    // Official self-host web continues to the password form; cloud Bitwarden
    // would show "Check your email" instead.
    await expect(page.getByRole('heading', { name: /set a strong password/i })).toBeVisible({ timeout: 30_000 });
  });
});
