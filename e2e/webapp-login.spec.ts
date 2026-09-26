import { pbkdf2Sync } from 'node:crypto';
import { test, expect, type Page } from '@playwright/test';

const email = 'person@example.com';
const password = 'Browser-test-password!';
const maskedEmail = 've****@example.net';
const sessionToken = 'email-session-token';
const masterPasswordHash = pbkdf2Sync(pbkdf2Sync(password, email, 600000, 32, 'sha256'), password, 1, 32, 'sha256').toString('base64');

test.use({ locale: 'en-US', serviceWorkers: 'block' });

async function openChallenge(page: Page, providers: number[] | 'new-device', firstSendFails = false) {
  const loginRequests: URLSearchParams[] = [];
  const sendRequests: Record<string, unknown>[] = [];
  const resendRequests: Record<string, unknown>[] = [];
  await page.route((url) => /^\/(api|identity)\//.test(url.pathname), async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/web-bootstrap') {
      return route.fulfill({ json: { defaultKdfIterations: 600000, registrationInviteRequired: true } });
    }
    if (path === '/identity/connect/token') {
      loginRequests.push(new URLSearchParams(route.request().postData() || ''));
      if (providers === 'new-device') {
        const description = loginRequests.length === 1 ? 'New device verification required' : 'Invalid New Device OTP';
        return route.fulfill({
          status: 400,
          json: {
            error: 'device_error',
            error_description: description,
            ErrorModel: { Message: description.toLowerCase(), Object: 'error' },
          },
        });
      }
      return route.fulfill({
        status: 400,
        json: loginRequests.length === 1 ? {
          error: 'invalid_grant',
          error_description: 'Two factor required.',
          TwoFactorProviders: providers,
          TwoFactorProviders2: Object.fromEntries(providers.map((provider) => [provider, provider === 1 ? { Email: maskedEmail } : null])),
          Email: email,
          SsoEmail2faSessionToken: sessionToken,
        } : { error: 'invalid_grant', error_description: 'Invalid email verification code.' },
      });
    }
    if (path === '/api/two-factor/send-email-login') {
      sendRequests.push(route.request().postDataJSON());
      return firstSendFails && sendRequests.length === 1
        ? route.fulfill({ status: 503, json: { error_description: 'Email delivery unavailable.' } })
        : route.fulfill({ json: '' });
    }
    if (path === '/api/accounts/resend-new-device-otp') {
      expect(route.request().method()).toBe('POST');
      resendRequests.push(route.request().postDataJSON());
      return route.fulfill({ json: '' });
    }
    return route.fulfill({ status: 404, json: {} });
  });
  await page.goto('/login');
  await page.getByLabel('Email', { exact: true }).fill(email);
  await page.getByLabel('Master Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Log In', exact: true }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  expect(loginRequests).toHaveLength(1);
  expect(loginRequests[0].get('password')).toBe(masterPasswordHash);
  expect(loginRequests[0].get('deviceIdentifier')).toBeTruthy();
  return { loginRequests, sendRequests, resendRequests };
}

test('Email 2FA preserves its challenge after send failure, resend, and invalid code', async ({ page }) => {
  const { loginRequests, sendRequests } = await openChallenge(page, [1], true);
  const dialog = page.getByRole('dialog');
  const code = dialog.getByLabel('Email verification code', { exact: true });
  await expect(code).toBeVisible();
  await expect(dialog.getByText(`Check ${maskedEmail} for your verification code.`, { exact: true })).toBeVisible();
  await expect(page.getByText('Email delivery unavailable.', { exact: true })).toBeVisible();
  expect(sendRequests).toEqual([{
    email,
    masterPasswordHash,
    ssoEmail2FaSessionToken: sessionToken,
    deviceIdentifier: loginRequests[0].get('deviceIdentifier'),
    authRequestId: '',
    authRequestAccessCode: '',
  }]);

  await dialog.getByRole('button', { name: 'Resend code', exact: true }).click();
  await expect.poll(() => sendRequests.length).toBe(2);
  await expect(dialog.getByRole('button', { name: 'Resend code', exact: true })).toBeEnabled();
  expect(sendRequests[1]).toEqual(sendRequests[0]);
  await code.fill(' 123456 ');
  await dialog.getByRole('button', { name: 'Verify', exact: true }).click();
  await expect(page.getByText('Invalid email verification code.', { exact: true })).toBeVisible();
  expect(loginRequests).toHaveLength(2);
  expect(Object.fromEntries(loginRequests[1])).toMatchObject({
    grant_type: 'password',
    username: email,
    password: masterPasswordHash,
    deviceIdentifier: loginRequests[0].get('deviceIdentifier'),
    twoFactorProvider: '1',
    twoFactorToken: '123456',
  });
  await expect(code).toBeVisible();
  await expect(dialog.getByRole('button', { name: 'Resend code', exact: true })).toBeEnabled();
  expect(sendRequests).toHaveLength(2);
});

test('selecting Email sends a code while the default authenticator does not', async ({ page }) => {
  const { sendRequests } = await openChallenge(page, [0, 1]);
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByLabel('TOTP Code', { exact: true })).toBeVisible();
  await dialog.getByRole('button', { name: 'Select another verification method', exact: true }).click();
  await expect(dialog.getByRole('button', { name: 'Email', exact: true })).toBeVisible();
  expect(sendRequests).toHaveLength(0);
  await dialog.getByRole('button', { name: 'Email', exact: true }).click();
  await expect(dialog.getByLabel('Email verification code', { exact: true })).toBeVisible();
  await expect(dialog.getByText(`Check ${maskedEmail} for your verification code.`, { exact: true })).toBeVisible();
  await expect.poll(() => sendRequests.length).toBe(1);
  expect(sendRequests[0]).toMatchObject({ email, masterPasswordHash, ssoEmail2FaSessionToken: sessionToken });
});

test('new-device verification retains its challenge and only resends on request', async ({ page }) => {
  const { loginRequests, sendRequests, resendRequests } = await openChallenge(page, 'new-device');
  const dialog = page.getByRole('dialog', { name: 'Verify new device', exact: true });
  const code = dialog.getByLabel('Email verification code', { exact: true });
  await expect(code).toBeVisible();
  await expect(dialog.getByText(`Check ${email} for a code to verify this device.`, { exact: true })).toBeVisible();
  await expect(dialog.getByRole('checkbox')).toHaveCount(0);
  await expect(dialog.getByRole('button', { name: 'Use Recovery Code', exact: true })).toHaveCount(0);
  await expect(dialog.getByRole('button', { name: 'Select another verification method', exact: true })).toHaveCount(0);
  expect(sendRequests).toHaveLength(0);
  expect(resendRequests).toHaveLength(0);

  await code.fill(' 123456 ');
  await dialog.getByRole('button', { name: 'Verify', exact: true }).click();
  await expect(page.getByText('The verification code is invalid. Try again.', { exact: true })).toBeVisible();
  await expect(code).toBeVisible();
  expect(loginRequests).toHaveLength(2);
  expect(resendRequests).toHaveLength(0);

  await dialog.getByRole('button', { name: 'Resend code', exact: true }).click();
  await expect.poll(() => resendRequests.length).toBe(1);
  await expect(dialog.getByRole('button', { name: 'Resend code', exact: true })).toBeEnabled();
  expect(resendRequests).toEqual([{ email, masterPasswordHash }]);
  await code.fill(' 654321 ');
  await dialog.getByRole('button', { name: 'Verify', exact: true }).click();
  await expect.poll(() => loginRequests.length).toBe(3);
  await expect(dialog.getByRole('button', { name: 'Verify', exact: true })).toBeEnabled();
  for (const [index, token] of ['123456', '654321'].entries()) {
    const request = loginRequests[index + 1];
    expect(Object.fromEntries(request)).toMatchObject({
      grant_type: 'password',
      username: email,
      password: masterPasswordHash,
      deviceIdentifier: loginRequests[0].get('deviceIdentifier'),
      newDeviceOtp: token,
    });
    expect(request.has('twoFactorProvider')).toBe(false);
    expect(request.has('twoFactorToken')).toBe(false);
    expect(request.has('twoFactorRemember')).toBe(false);
  }
  expect(sendRequests).toHaveLength(0);
  expect(resendRequests).toHaveLength(1);
});
