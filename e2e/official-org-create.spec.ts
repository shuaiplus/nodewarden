import { readFileSync, writeFileSync } from 'node:fs';
import { test, expect } from '@playwright/test';

// Opt in with E2E_OFFICIAL_ORG_FIXTURE: a private JSON file containing
// { pagesOrigin, email, password, run? }. Use a freshly registered synthetic account
// with real encrypted keys, its real password, and no organizations on a disposable Worker.
// Use HTTPS localhost: the official SDK rejects plain HTTP even on loopback.
const fixturePath = process.env.E2E_OFFICIAL_ORG_FIXTURE;
const fixture: { pagesOrigin: string; email: string; password: string; run?: string } | null = fixturePath
  ? JSON.parse(readFileSync(fixturePath, 'utf8')) : null;
const local = (() => {
  try { const url = new URL(fixture?.pagesOrigin ?? ''); return ['http:', 'https:'].includes(url.protocol) && url.hostname === 'localhost'; }
  catch { return false; }
})();
test.use({ locale: 'en-US', ignoreHTTPSErrors: true });
test.setTimeout(60_000);

test('official self-host web creates a named organization and encrypted SM project without a license file', async ({ page, context }) => {
  test.skip(!local, 'Requires E2E_OFFICIAL_ORG_FIXTURE for disposable localhost Worker + official Pages/proxy.');
  page.setDefaultTimeout(15_000);
  const origin = fixture!.pagesOrigin;
  const version = await page.request.get(`${origin}/version.json`);
  expect(version.status()).toBe(200);
  expect((await version.json()).version).toBe('2026.9.0');
  await context.route('**/*', route => new URL(route.request().url()).host === new URL(origin).host ? route.continue() : route.abort());
  const orgRequests: Array<{ path: string; body: Record<string, unknown> }> = [];
  page.on('request', request => {
    const path = new URL(request.url()).pathname;
    if (request.method() === 'POST' && (path === '/api/organizations' || path.startsWith('/api/organizations/licenses'))) {
      orgRequests.push({ path, body: request.postDataJSON() });
    }
  });
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

  await page.goto(`${origin}/#/sm-landing`);
  await page.getByRole('button', { name: /^try it now$/i }).click();
  const form = page.locator('organization-self-hosting-license-uploader');
  const name = form.getByRole('textbox', { name: /organization name/i });
  await expect(name).toBeVisible();
  await expect(form.locator('input[type="file"]')).toHaveCount(0);
  await expect(page.getByText(/upload a valid license file/i)).toHaveCount(0);
  const create = form.getByRole('button', { name: /^create$/i });
  for (const blank of ['', '   ']) {
    await name.fill(blank);
    await create.click();
    await expect.poll(() => name.evaluate((input: HTMLInputElement) => !input.checkValidity() || input.classList.contains('ng-invalid'))).toBe(true);
    expect(orgRequests).toHaveLength(0);
  }

  const organizationName = 'Local official organization';
  await name.fill(`  ${organizationName}  `);
  const created = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/organizations');
  await create.click();
  const response = await created;
  expect(response.status(), await response.text()).toBe(200);
  const organization = await response.json();
  const request = response.request().postDataJSON();
  expect(request.name).toBe(organizationName);
  expect(request.key).toMatch(/^[3-6]\./);
  expect(request.collectionName).toMatch(/^2\.[^|]+\|[^|]+\|[^|]+$/);
  expect(request.keys.encryptedPrivateKey).toMatch(/^2\.[^|]+\|[^|]+\|[^|]+$/);
  expect(request.keys.publicKey).toMatch(/^[A-Za-z0-9+/]+=*$/);
  expect(orgRequests.map(item => item.path)).toEqual(['/api/organizations']);
  await expect.poll(() => new URL(page.url()).hash).toMatch(new RegExp(`^#/sm/${organization.id}(?:/|$)`));

  await page.goto(`${origin}/#/sm/${organization.id}/projects`);
  await page.getByRole('button', { name: /(?:new|add|create) project$/i }).click();
  const dialog = page.getByRole('dialog');
  const projectName = 'Encrypted project from official web';
  await dialog.getByRole('textbox', { name: /project name/i }).fill(projectName);
  const projectCreated = page.waitForResponse(result => result.request().method() === 'POST' && new URL(result.url()).pathname === `/api/organizations/${organization.id}/projects`);
  await dialog.getByRole('button', { name: /^save$/i }).click();
  const projectResponse = await projectCreated;
  expect(projectResponse.status(), await projectResponse.text()).toBe(200);
  const project = await projectResponse.json();
  const projectRequest = projectResponse.request().postDataJSON();
  expect(projectRequest.name).toMatch(/^2\.[^|]+\|[^|]+\|[^|]+$/);
  expect(projectRequest.name).not.toBe(projectName);
  await expect(page.getByText(projectName, { exact: true }).first()).toBeVisible();
  const read = await page.request.get(`${origin}/api/projects/${project.id}`, {
    headers: { Authorization: projectResponse.request().headers().authorization },
  });
  expect(read.status()).toBe(200);
  expect((await read.json()).name).toBe(projectRequest.name);
  if (fixture!.run) {
    writeFileSync(`${fixture!.run}/created-resources.json`, JSON.stringify({ organizationId: organization.id, organizationRequest: request, projectId: project.id, projectRequest }, null, 2));
    await page.screenshot({ path: `${fixture!.run}/official-org-project.png`, fullPage: true });
  }
});
