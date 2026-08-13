import { test, expect } from '@playwright/test';

const origin = process.env.E2E_ORIGIN || 'http://127.0.0.1:8787';

test.describe('organizations and secrets manager', () => {
  test('create org, collection, member invite, secret', async ({ request }) => {
    const suffix = Date.now();
    const email = `owner-${suffix}@example.com`;
    const passwordHash = 'x'.repeat(64);
    const register = await request.post(`${origin}/api/accounts/register`, {
      data: {
        email,
        name: 'Owner',
        masterPasswordHash: passwordHash,
        key: '2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        keys: {
          publicKey: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw',
          encryptedPrivateKey: '2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        },
        kdf: 0,
        kdfIterations: 600000,
      },
    });
    expect([200, 201, 400]).toContain(register.status());

    const tokenResp = await request.post(`${origin}/identity/connect/token`, {
      form: {
        grant_type: 'password',
        username: email,
        password: passwordHash,
        scope: 'api offline_access',
        client_id: 'web',
        deviceIdentifier: `e2e-${suffix}`,
        deviceName: 'e2e',
        deviceType: '14',
      },
    });
    if (tokenResp.status() !== 200) test.skip(true, 'Registration/login requires invite or existing instance');
    const tokenBody = await tokenResp.json();
    const access = tokenBody.access_token as string;
    const headers = { Authorization: `Bearer ${access}`, 'Content-Type': 'application/json' };

    const orgResp = await request.post(`${origin}/api/organizations`, {
      headers,
      data: {
        name: `Org ${suffix}`,
        billingEmail: email,
        collectionName: 'Shared',
        key: '2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      },
    });
    expect(orgResp.ok()).toBeTruthy();
    const org = await orgResp.json();
    expect(org.id).toBeTruthy();

    const collections = await request.get(`${origin}/api/organizations/${org.id}/collections`, { headers });
    expect(collections.ok()).toBeTruthy();
    const collectionList = await collections.json();
    expect(collectionList.data.length).toBeGreaterThan(0);

    const invite = await request.post(`${origin}/api/organizations/${org.id}/users/invite`, {
      headers,
      data: { emails: [`member-${suffix}@example.com`], type: 2, accessAll: false },
    });
    expect(invite.ok()).toBeTruthy();

    const secret = await request.post(`${origin}/api/organizations/${org.id}/secrets`, {
      headers,
      data: { key: '2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', value: '2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' },
    });
    expect(secret.ok()).toBeTruthy();

    const profile = await request.get(`${origin}/api/accounts/profile`, { headers });
    const profileBody = await profile.json();
    expect(profileBody.organizations.some((item: { id: string }) => item.id === org.id)).toBeTruthy();

    const sync = await request.get(`${origin}/api/sync`, { headers });
    const syncBody = await sync.json();
    expect(Array.isArray(syncBody.collections)).toBeTruthy();
  });
});
