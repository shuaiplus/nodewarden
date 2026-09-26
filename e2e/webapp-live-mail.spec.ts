import { readFileSync } from 'node:fs';
import { test, expect } from '@playwright/test';
import { readLocalEmailCode } from '../scripts/support/local-email';

interface Fixture {
  kind: string; email: string; password: string; factorEmail: string; knownDevice: string; itemName: string; cipherId: string;
}
const fixturePath = process.env.E2E_LIVE_MAIL_FIXTURES;
const fixtures: { origin: string; log: string; accounts: Fixture[] } | null = fixturePath ? JSON.parse(readFileSync(fixturePath, 'utf8')) : null;
const local = fixtures && new URL(fixtures.origin).protocol === 'http:' && new URL(fixtures.origin).hostname === 'localhost';
test.use({ locale: 'en-US' });
test.setTimeout(60_000);

for (const kind of ['email-2fa', 'new-device']) {
  test(`live ${kind}: local email code unlocks and decrypts the vault`, async ({ page }) => {
    test.skip(!local, 'Run npm run test:e2e:live-mail for isolated local Wrangler/email fixtures.');
    const user = fixtures!.accounts.find(account => account.kind === kind)!;
    const failures: string[] = [];
    page.on('pageerror', error => failures.push(error.message));
    await page.goto(`${fixtures!.origin}/login`);
    await page.getByLabel('Email', { exact: true }).fill(user.email);
    await page.getByLabel('Master Password', { exact: true }).fill(user.password);
    const started = Date.now();
    const challengeResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/identity/connect/token' && response.status() === 400);
    await page.getByRole('button', { name: 'Log In', exact: true }).click();
    const challenge = await challengeResponse;
    const device = new URLSearchParams(challenge.request().postData()!).get('deviceIdentifier');
    expect(device).toBeTruthy();
    expect(device).not.toBe(user.knownDevice);
    const body = await challenge.json();
    if (kind === 'new-device') expect(body.ErrorModel.Message).toBe('new device verification required');
    else expect(body.TwoFactorProviders.map(String)).toContain('1');
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    const input = dialog.getByLabel('Email verification code', { exact: true });
    await expect(input).toBeVisible();
    let mail: ReturnType<typeof readLocalEmailCode> = null;
    await expect.poll(() => {
      mail = readLocalEmailCode(fixtures!.log, user.factorEmail, started);
      return mail?.code;
    }, { timeout: 15000 }).toMatch(/^\d{6}$/);
    if (kind === 'new-device') expect(mail!.text).toContain('Consider enabling two-step login');

    const wrong = String((Number(mail!.code) + 1) % 1_000_000).padStart(6, '0');
    const rejected = page.waitForResponse(response => new URL(response.url()).pathname === '/identity/connect/token' && response.status() === 400);
    await input.fill(wrong);
    await dialog.getByRole('button', { name: 'Verify', exact: true }).click();
    await rejected;
    await expect(input).toBeVisible();
    const resendStarted = Date.now();
    await dialog.getByRole('button', { name: 'Resend code', exact: true }).click();
    await expect.poll(() => {
      mail = readLocalEmailCode(fixtures!.log, user.factorEmail, resendStarted);
      return mail?.code;
    }, { timeout: 15000 }).toMatch(/^\d{6}$/);
    await input.fill(mail!.code);
    const synced = page.waitForResponse(response => new URL(response.url()).pathname === '/api/sync' && response.status() === 200);
    await dialog.getByRole('button', { name: 'Verify', exact: true }).click();
    const response = await synced;
    const vault = await response.json();
    expect(vault.ciphers.some((cipher: { id: string }) => cipher.id === user.cipherId)).toBe(true);
    expect(JSON.stringify(vault)).not.toContain(user.itemName);
    await expect(page.getByRole('heading', { name: user.itemName, exact: true })).toBeVisible();
    await expect(dialog).not.toBeVisible();
    expect(failures).toEqual([]);
  });
}
