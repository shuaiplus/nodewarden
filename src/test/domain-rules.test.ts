import assert from 'node:assert/strict';
import test from 'node:test';
import { authedFetch, createTestEnv, seedUser } from './support/env';

// The domain normalizers drop malformed entries instead of rejecting the body, and a field that is
// present (even as null) replaces the stored rules while an absent one keeps them.
test('domain rules drop malformed entries, keep absent fields and clear present nulls', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const update = async (body: unknown) =>
    (
      await authedFetch(env, { method: 'PUT', path: '/api/settings/domains', body, userId: user.id })
    ).json() as Promise<any>;

  const saved = await update({
    CustomEquivalentDomains: [
      ['a.com', 'www.b.com'],
      ['b.com', 'a.com'],
      ['solo.com'],
      'junk',
      { Id: 'kept', Domains: ['c.com', 'd.com'], Excluded: true },
    ],
    ExcludedGlobalEquivalentDomains: [2, { type: 3, excluded: false }, { type: 4, excluded: true }, 2, 'x', 999999],
  });
  assert.deepEqual(saved.customEquivalentDomains, [
    { id: 'custom:a.com|b.com:0', domains: ['a.com', 'b.com'], excluded: false },
    { id: 'kept', domains: ['c.com', 'd.com'], excluded: true },
  ]);
  assert.deepEqual(
    saved.globalEquivalentDomains.filter((entry: any) => entry.excluded).map((entry: any) => entry.type),
    [2, 4],
  );

  const kept = await update({ equivalentDomains: undefined });
  assert.deepEqual(kept.customEquivalentDomains, saved.customEquivalentDomains);
  assert.deepEqual(await update('not an object'), kept);

  const cleared = await update({ customEquivalentDomains: null, globalEquivalentDomains: null });
  assert.deepEqual([cleared.customEquivalentDomains, cleared.equivalentDomains], [[], []]);
  assert.equal(
    cleared.globalEquivalentDomains.some((entry: any) => entry.excluded),
    false,
  );
});
