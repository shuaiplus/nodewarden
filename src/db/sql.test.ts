import assert from 'node:assert/strict';
import { test } from 'node:test';
import { count, eq, inArray } from 'drizzle-orm';

import { createTestEnv, seedUser } from '../test/support/env';
import { getOrm } from './client';
import { config, users } from './schema';
import {
  SINGLE_ROW, bound, boundRow, caseWhen, castInteger, coalesce, excluded, jsonExtract, jsonRemove, jsonSet, jsonValues,
  likeEscaped, lower, nullIf, plus, scalar, unmapped,
} from './sql';

test('boundRow selects plain values as one row keyed like the input', async () => {
  const env = await createTestEnv();
  const values = { text: 'value', count: 3, missing: null };
  assert.deepEqual(await getOrm(env.DB).select(boundRow(values)).from(SINGLE_ROW).get(), values);
});

test('sql helpers evaluate on D1 exactly as the SQL they stand for', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const orm = getOrm(env.DB);
  const row = await orm.select({
    bound: bound('text'),
    plus: plus(2, 3),
    lower: lower('MiXeD'),
    castInteger: castInteger('42'),
    coalesce: coalesce(null, 'fallback'),
    nullIf: nullIf('', ''),
    caseThen: caseWhen(eq(bound(1), 1), 'yes', 'no'),
    caseNull: caseWhen(eq(bound(1), 2), 'yes'),
    likeLiteralPercent: likeEscaped('50%_off', '50\\%\\_%'),
    likeNoMatch: likeEscaped('500_off', '50\\%%'),
    jsonExtract: jsonExtract('{"a":{"b":7}}', '$.a.b'),
    jsonSet: jsonSet('{"a":1}', '$.b', 2),
    jsonRemove: jsonRemove('{"a":1,"b":2,"c":3}', '$.a', '$.c'),
    listed: inArray(bound('b'), jsonValues(['a', 'b'])),
    notListed: inArray(bound('z'), jsonValues(['a', 'b'])),
    users: scalar<number>(orm.select({ total: count() }).from(users)),
  }).from(SINGLE_ROW).get();
  assert.deepEqual(row, {
    bound: 'text', plus: 5, lower: 'mixed', castInteger: 42, coalesce: 'fallback', nullIf: null, caseThen: 'yes', caseNull: null,
    likeLiteralPercent: 1, likeNoMatch: 0, jsonExtract: 7, jsonSet: '{"a":1,"b":2}', jsonRemove: '{"b":2}', listed: 1, notListed: 0, users: 1,
  });

  // unmapped passes the stored value through untouched (backup exports rely on it if a column ever gains a mode).
  const [verified] = await orm.select({ mapped: users.emailVerified, stored: unmapped<number>(users.emailVerified) }).from(users).where(eq(users.id, user.id));
  assert.equal(verified.stored, verified.mapped);

  // excluded() is the value the conflicting insert carried.
  await orm.insert(config).values({ key: 'helper-probe', value: 'first' });
  await orm.insert(config).values({ key: 'helper-probe', value: 'second' }).onConflictDoUpdate({ target: config.key, set: { value: excluded(config.value) } });
  assert.equal((await orm.select({ value: config.value }).from(config).where(eq(config.key, 'helper-probe')).get())?.value, 'second');
});
