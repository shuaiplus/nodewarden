import { readFileSync, writeFileSync } from 'node:fs';
import { test, expect } from '@playwright/test';

// Opt in with E2E_OFFICIAL_REPORT_FIXTURE, a private JSON file described below.
// Use a fresh synthetic account on disposable localhost Worker + HTTPS Pages, real
// encrypted user/org keys, one org login with a locally encrypted weak password,
// one encrypted project, and one group granting the account access to that collection.
// Create the project and cipher through the API after installing event hooks.
// Nothing in this test mocks API responses or sends plaintext vault contents.
interface Fixture {
  pagesOrigin: string; email: string; password: string; organizationId: string;
  cipherId: string; weakCipherName: string; projectId: string; run?: string;
}
const path = process.env.E2E_OFFICIAL_REPORT_FIXTURE;
const fixture: Fixture | null = path ? JSON.parse(readFileSync(path, 'utf8')) : null;
const local = (() => {
  try { const url = new URL(fixture?.pagesOrigin ?? ''); return url.protocol === 'https:' && url.hostname === 'localhost'; }
  catch { return false; }
})();
test.use({ locale: 'en-US', ignoreHTTPSErrors: true });
test.setTimeout(60_000);
test.beforeEach(async ({ page, context }) => {
  test.skip(!local, 'Requires E2E_OFFICIAL_REPORT_FIXTURE for disposable HTTPS localhost.');
  const origin = fixture!.pagesOrigin;
  const version = await page.request.get(`${origin}/version.json`);
  expect(version.status()).toBe(200);
  expect((await version.json()).version).toBe('2026.9.0');
  await context.route('**/*', route => new URL(route.request().url()).host === new URL(origin).host ? route.continue() : route.abort());
  await page.goto(`${origin}/#/login`);
  await page.getByRole('textbox', { name: /email address/i }).fill(fixture!.email);
  const password = page.getByLabel(/^master password/i);
  if (!await password.isVisible()) await page.getByRole('button', { name: /^continue$/i }).click();
  await password.fill(fixture!.password);
  const synced = page.waitForResponse(response => new URL(response.url()).pathname === '/api/sync' && response.status() === 200);
  await page.getByRole('button', { name: /^log in( with master password)?$/i }).click();
  await synced;
  await page.getByRole('button', { name: /^add it later$/i }).click();
  await page.getByRole('link', { name: /^skip to web app$/i }).click();
  await expect(page).toHaveURL(/#\/vault/);
  await page.getByRole('dialog').getByRole('button', { name: /^skip$/i }).click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
});

test('official organization reports remediate encrypted items and display typed events', async ({ page }) => {
  const f = fixture!;
  const reports = `${f.pagesOrigin}/#/organizations/${f.organizationId}/reporting/reports`;
  const details = page.waitForResponse(response => new URL(response.url()).pathname === '/api/ciphers/organization-details');
  await page.goto(`${reports}/weak-passwords-report`);
  const response = await details;
  expect(response.status(), await response.text()).toBe(200);
  const rows = (await response.json()).data;
  const cipher = rows.find((row: { id: string }) => row.id === f.cipherId);
  expect(cipher.name).toMatch(/^2\.[^|]+\|[^|]+\|[^|]+$/);
  expect(cipher.login.password).toMatch(/^2\.[^|]+\|[^|]+\|[^|]+$/);
  await expect(page.getByRole('heading', { name: 'Weak passwords', exact: true })).toBeVisible();
  await expect(page.getByText(f.weakCipherName, { exact: true })).toBeVisible();
  if (f.run) await page.screenshot({ path: `${f.run}/weak-password-report.png`, fullPage: true });
  await page.getByRole('link', { name: f.weakCipherName, exact: true }).click();
  const itemDialog = page.getByRole('dialog');
  await itemDialog.getByRole('button', { name: 'Edit', exact: true }).click();
  const strongPassword = 'Local-only-Y8v!c4KQ7j@nF3zT5#eS9uD2';
  await itemDialog.getByLabel('Password', { exact: true }).fill(strongPassword);
  const saved = page.waitForResponse(result => result.request().method() === 'PUT' && new URL(result.url()).pathname === `/api/ciphers/${f.cipherId}/admin`);
  await itemDialog.getByRole('button', { name: 'Save', exact: true }).click();
  const saveResponse = await saved;
  expect(saveResponse.status(), await saveResponse.text()).toBe(200);
  const saveRequest = saveResponse.request().postDataJSON();
  expect(saveRequest.login.password).toMatch(/^2\.[^|]+\|[^|]+\|[^|]+$/);
  expect(JSON.stringify(saveRequest)).not.toContain(strongPassword);
  expect(saveRequest.login.password).not.toBe(cipher.login.password);
  expect((await saveResponse.json()).login.password).toBe(saveRequest.login.password);
  // 2026.9.0 keeps a saved item open in view mode; the report refreshes once the dialog closes.
  await expect(itemDialog.getByRole('heading', { name: 'View Login', exact: true })).toBeVisible();
  const refreshed = page.waitForResponse(result => result.request().method() === 'GET' && new URL(result.url()).pathname === `/api/ciphers/${f.cipherId}/admin`);
  await itemDialog.getByRole('button', { name: 'Close', exact: true }).click();
  await expect(itemDialog).not.toBeVisible();
  expect((await refreshed).status()).toBe(200);
  await expect(page.getByText(f.weakCipherName, { exact: true })).not.toBeVisible();
  const reloaded = page.waitForResponse(result => new URL(result.url()).pathname === '/api/ciphers/organization-details');
  await page.reload();
  // A full reload locks the vault; unlocking returns to the report route and refetches it.
  await page.getByLabel(/^master password/i).fill(f.password);
  await page.getByRole('button', { name: 'Unlock', exact: true }).click();
  const stored = (await (await reloaded).json()).data.find((row: { id: string }) => row.id === f.cipherId);
  expect(stored.login.password).toBe(saveRequest.login.password);
  await expect(page.getByText('No items in your vault have weak passwords.', { exact: true })).toBeVisible();
  if (f.run) writeFileSync(`${f.run}/encrypted-remediation.json`, JSON.stringify(saveRequest, null, 2));

  await page.goto(reports);
  await page.getByRole('link', { name: /member access/i }).click();
  await expect(page.getByRole('heading', { name: 'Member access', exact: true })).toBeVisible();
  const member = page.getByRole('row').filter({ hasText: f.email });
  await expect(member).toBeVisible();
  await expect(member.getByRole('cell')).toHaveText([new RegExp(f.email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), '1', '1', '1']);
  if (f.run) await page.screenshot({ path: `${f.run}/member-access-report.png`, fullPage: true });

  const eventPath = `/api/organizations/${f.organizationId}/events`;
  const eventsResponse = page.waitForResponse(response => new URL(response.url()).pathname === eventPath);
  await page.goto(`${f.pagesOrigin}/#/organizations/${f.organizationId}/reporting/events`);
  const eventResponse = await eventsResponse;
  expect(eventResponse.status(), await eventResponse.text()).toBe(200);
  const events = (await eventResponse.json()).data;
  expect(events).toEqual(expect.arrayContaining([
    expect.objectContaining({ type: 1100, cipherId: f.cipherId, organizationId: f.organizationId }),
    expect.objectContaining({ type: 1101, cipherId: f.cipherId, organizationId: f.organizationId }),
    expect.objectContaining({ type: 2201, projectId: f.projectId, organizationId: f.organizationId }),
  ]));
  const table = page.getByTestId('events-table');
  await expect(table.getByRole('row').filter({ hasText: `Created item ${f.cipherId.slice(0, 8)}` })).toBeVisible();
  await expect(table.getByRole('row').filter({ hasText: `Edited item ${f.cipherId.slice(0, 8)}` })).toBeVisible();
  await expect(table.getByRole('row').filter({ hasText: `Created a new project with identifier: ${f.projectId.slice(0, 8)}` })).toBeVisible();
  if (f.run) {
    writeFileSync(`${f.run}/typed-events.json`, JSON.stringify(events, null, 2));
    await page.screenshot({ path: `${f.run}/typed-event-log.png`, fullPage: true });
  }
  const from = page.getByLabel('From', { exact: true });
  const to = page.getByLabel('To', { exact: true });
  const originalFrom = await from.inputValue();
  const originalTo = await to.inputValue();
  await from.fill('2000-01-01T00:00');
  await to.fill('2000-01-02T00:00');
  const emptyResponse = page.waitForResponse(result => new URL(result.url()).pathname === eventPath);
  await page.getByRole('button', { name: 'Update', exact: true }).click();
  expect((await (await emptyResponse).json()).data).toEqual([]);
  await expect(page.getByText('There are no events to list.', { exact: true })).toBeVisible();
  await from.fill(originalFrom);
  await to.fill(originalTo);
  await page.getByRole('button', { name: 'Update', exact: true }).click();
  await expect(table.getByRole('row').filter({ hasText: `Created item ${f.cipherId.slice(0, 8)}` })).toBeVisible();
});
