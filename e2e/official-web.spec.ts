import { test, expect } from '@playwright/test';

const workerOrigin = process.env.E2E_ORIGIN || 'http://127.0.0.1:8787';
const officialWebOrigin = process.env.OFFICIAL_WEB_ORIGIN || 'http://127.0.0.1:8080';

test.describe('official Bitwarden web against NodeWarden', () => {
  test('identity register/send-verification and finish work without email', async ({ request }) => {
    const suffix = Date.now();
    const email = `official-${suffix}@example.com`;
    const origin = workerOrigin;

    const start = await request.post(`${origin}/identity/accounts/register/send-verification-email`, {
      headers: { Origin: origin, 'Content-Type': 'application/json' },
      data: { email, name: 'Official', receiveMarketingEmails: false },
    });
    expect(start.ok(), await start.text()).toBeTruthy();
    const token = await start.json();
    expect(typeof token).toBe('string');
    expect(String(token).split('.').length).toBe(3);

    const finish = await request.post(`${origin}/identity/accounts/register/finish`, {
      headers: { Origin: origin, 'Content-Type': 'application/json' },
      data: {
        email,
        name: 'Official',
        emailVerificationToken: token,
        userAsymmetricKeys: {
          publicKey: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw',
          encryptedPrivateKey: '2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        },
        masterPasswordAuthentication: {
          salt: email,
          kdf: { kdfType: 0, iterations: 600000 },
          masterPasswordAuthenticationHash: 'x'.repeat(64),
        },
        masterPasswordUnlock: {
          salt: email,
          kdf: { kdfType: 0, iterations: 600000 },
          masterKeyWrappedUserKey: '2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        },
      },
    });
    expect(finish.ok(), await finish.text()).toBeTruthy();
    const body = await finish.json();
    expect(body.object).toBe('register');
  });

  test('official web vault loads and talks to the worker config API', async ({ page, request }) => {
    const config = await request.get(`${officialWebOrigin}/api/config`, {
      headers: { 'Accept-Encoding': 'identity' },
    });
    expect(config.ok(), await config.text()).toBeTruthy();
    const payload = await config.json();
    expect(payload.object).toBe('config');
    expect(payload.environment?.api).toContain('/api');

    await page.goto(officialWebOrigin);
    await expect(page).toHaveTitle(/Bitwarden Web vault/i);
    await expect(page.getByLabel(/Email address/i)).toBeVisible({ timeout: 30_000 });
  });
});
