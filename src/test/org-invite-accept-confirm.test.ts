import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';

import { LIMITS } from '../config/limits';
import { MembershipStatus } from '../services/org-types';
import * as orgRepo from '../services/storage-org-repo';
import type { Env, User } from '../types';
import { ORG_INVITE_TTL_DAYS, verifyHs256Jwt } from '../utils/jwt';
import { sanitizeForEmail } from '../services/mail';
import { D1_MAX_BOUND_PARAMETERS } from './support/d1-sqlite';
import { authedFetch, createTestEnv, seedUser, captureEmail, MAILABLE_DOMAIN, type SentEmail } from './support/env';
import { createOrg, errorMessage, TEST_ORG_NAME } from './support/sm';

const { createOwnedOrganization } = await import('../handlers/organizations');

// Upstream OrganizationService always stores invites as Invited with no user, and only
// AcceptOrgUserCommand (after checking the emailed token) binds the user. Without that, anyone can
// invite and confirm an existing account and push their org policies onto it.
const OFFICIAL_WEB_ORIGIN = 'https://web.example.test';
const MEMBER_KEY = '4.dGVzdA==';
const INVITE_LINK_PATTERN = /https:\/\/\S+accept-organization\?\S+/;
// seedUser's example.test addresses are RFC 6761 names, which invites never mail.
const FORWARDED_HOST = 'evil.example';
// Upstream StrictEmailAddressListAttribute limits.
const MAX_INVITE_EMAILS = 20;
const MAX_INVITE_EMAIL_LENGTH = 256;
const MS_PER_SECOND = 1000;
const MS_PER_DAY = 24 * 60 * 60 * MS_PER_SECOND;
// Upstream OrganizationUserBulkResponseModel passes this object name for every bulk member action.
const BULK_RESULT_OBJECT = 'OrganizationBulkConfirmResponseModel';

interface MemberBody {
  id: string;
  userId: string | null;
  name: string | null;
  email: string;
  status: number;
}

// The official web /#/accept-organization route reads these query params (DirectOrganizationInvite).
function inviteParams(email: SentEmail): URLSearchParams {
  const link = email.text?.match(INVITE_LINK_PATTERN)?.[0];
  assert.ok(link, 'invite email has no accept-organization link');
  assert.ok(link.startsWith(`${OFFICIAL_WEB_ORIGIN}/#/accept-organization?`), link);
  return new URLSearchParams(link.slice(link.indexOf('?') + 1));
}

// The token from the latest invite mail to the address, which a reinvite replaces.
function inviteToken(sent: SentEmail[], email: string): string | null {
  const latest = sent.filter((message) => message.to === email).at(-1);
  assert.ok(latest, `no invite email to ${email}`);
  return inviteParams(latest).get('token');
}

function seedMailableUser(env: Env): Promise<User> {
  return seedUser(env, { email: `${crypto.randomUUID()}@${MAILABLE_DOMAIN}` });
}

function postInvite(env: Env, owner: User, orgId: string, emails: string[], headers?: HeadersInit): Promise<Response> {
  return authedFetch(env, {
    method: 'POST',
    path: `/api/organizations/${orgId}/users/invite`,
    body: { emails, type: 2 },
    userId: owner.id,
    headers,
  });
}

async function invite(env: Env, owner: User, orgId: string, emails: string[], headers?: HeadersInit): Promise<void> {
  assert.equal((await postInvite(env, owner, orgId, emails, headers)).status, 200);
}

async function listMembers(env: Env, owner: User, orgId: string): Promise<MemberBody[]> {
  const response = await authedFetch(env, { path: `/api/organizations/${orgId}/users`, userId: owner.id });
  assert.equal(response.status, 200);
  const { data } = await response.json() as { data: MemberBody[] };
  return data;
}

async function findMember(env: Env, owner: User, orgId: string, email: string): Promise<MemberBody> {
  const found = (await listMembers(env, owner, orgId)).find((member) => member.email === email);
  assert.ok(found, `no member row for ${email}`);
  return found;
}

function accept(env: Env, user: User, orgId: string, memberId: string, body: Record<string, unknown>): Promise<Response> {
  return authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/users/${memberId}/accept`, body, userId: user.id });
}

async function revisionDate(env: Env, user: User): Promise<number> {
  const response = await authedFetch(env, { path: '/api/accounts/revision-date', userId: user.id });
  assert.equal(response.status, 200);
  return await response.json() as number;
}

function confirm(env: Env, owner: User, orgId: string, memberId: string, key: string): Promise<Response> {
  return authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/users/${memberId}/confirm`, body: { key }, userId: owner.id });
}

function reinvite(env: Env, caller: User, orgId: string, memberId: string): Promise<Response> {
  return authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/users/${memberId}/reinvite`, userId: caller.id });
}

function postBulk(env: Env, caller: User, orgId: string, action: 'confirm' | 'reinvite', body: Record<string, unknown>): Promise<Response> {
  return authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/users/${action}`, body, userId: caller.id });
}

// Upstream OrganizationUserBulkResponseModel list, as [id, error] pairs in response order. Official
// web counts an entry as done only when its error is the empty string.
async function bulkErrors(response: Response): Promise<Array<[string, string]>> {
  assert.equal(response.status, 200);
  const body = await response.json() as { object: string; data: Array<{ id: string; error: string; object: string }> };
  assert.equal(body.object, 'list');
  body.data.forEach((entry) => assert.equal(entry.object, BULK_RESULT_OBJECT));
  return body.data.map(({ id, error }) => [id, error]);
}

async function memberStatuses(env: Env, owner: User, orgId: string): Promise<Record<string, number>> {
  return Object.fromEntries((await listMembers(env, owner, orgId)).map(({ id, status }) => [id, status]));
}

// Invites a fresh account and accepts with its emailed token, leaving an Accepted row to confirm.
async function acceptedMember(env: Env, sent: SentEmail[], owner: User, orgId: string): Promise<{ id: string; user: User }> {
  const invitee = await seedMailableUser(env);
  await invite(env, owner, orgId, [invitee.email]);
  const memberId = (await findMember(env, owner, orgId, invitee.email)).id;
  assert.equal((await accept(env, invitee, orgId, memberId, { token: inviteToken(sent, invitee.email) })).status, 200);
  return { id: memberId, user: invitee };
}

async function invitedMember(env: Env, owner: User, orgId: string): Promise<{ id: string; email: string }> {
  const email = `${crypto.randomUUID()}@${MAILABLE_DOMAIN}`;
  await invite(env, owner, orgId, [email]);
  return { id: (await findMember(env, owner, orgId, email)).id, email };
}

async function postScimUser(env: Env, owner: User, orgId: string, email: string, body: unknown = { userName: email }): Promise<Response> {
  const scimKey = await authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/scim-key`, userId: owner.id });
  assert.equal(scimKey.status, 200);
  const { token } = await scimKey.json() as { token: string };
  return authedFetch(env, {
    method: 'POST',
    path: `/scim/v2/${orgId}/Users`,
    body,
    headers: { Authorization: `Bearer ${token}` },
  });
}

async function provisionViaScim(env: Env, owner: User, orgId: string, email: string): Promise<void> {
  assert.equal((await postScimUser(env, owner, orgId, email)).status, 201);
}

test('inviting an existing account keeps it Invited and unconfirmable until the invitee accepts with a token', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const invitee = await seedUser(env, { name: 'Invitee' });
  const orgId = await createOrg(env, owner);

  await invite(env, owner, orgId, [invitee.email]);
  const invited = await findMember(env, owner, orgId, invitee.email);
  assert.equal(invited.status, MembershipStatus.Invited);
  assert.equal(invited.userId, null);
  assert.equal(invited.name, null);

  const confirmed = await confirm(env, owner, orgId, invited.id, MEMBER_KEY);
  assert.equal(confirmed.status, 400);
  assert.equal(await errorMessage(confirmed), 'User not valid.');

  const tokenless = await accept(env, invitee, orgId, invited.id, {});
  assert.equal(tokenless.status, 400);
  assert.equal(await errorMessage(tokenless), 'The Token field is required.');

  const forged = await accept(env, invitee, orgId, invited.id, { token: 'forged' });
  assert.equal(forged.status, 400);
  assert.equal(await errorMessage(forged), 'Invalid token.');

  const missing = await accept(env, invitee, orgId, crypto.randomUUID(), { token: 'forged' });
  assert.equal(missing.status, 404);
  const otherOrgId = await createOrg(env, owner);
  const crossOrg = await accept(env, invitee, otherOrgId, invited.id, { token: 'forged' });
  assert.equal(crossOrg.status, 404);
  assert.equal(await errorMessage(crossOrg), 'Organization user mismatch');

  assert.equal((await findMember(env, owner, orgId, invitee.email)).status, MembershipStatus.Invited);
});

test('the emailed invite token only lets the invited account accept, and confirm then needs an RSA-wrapped key', async (context) => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const invitee = await seedMailableUser(env);
  const intruder = await seedUser(env);
  const orgId = await createOrg(env, owner);

  await invite(env, owner, orgId, [invitee.email]);
  assert.equal(capture.sent.length, 1);
  assert.equal(capture.sent[0].to, invitee.email);
  const params = inviteParams(capture.sent[0]);
  const memberId = (await findMember(env, owner, orgId, invitee.email)).id;
  assert.equal(params.get('organizationId'), orgId);
  assert.equal(params.get('organizationUserId'), memberId);
  assert.equal(params.get('email'), invitee.email);
  assert.equal(params.get('organizationName'), TEST_ORG_NAME);
  assert.equal(params.get('initOrganization'), 'false');
  assert.equal(params.get('orgUserHasExistingUser'), 'true');
  const token = params.get('token');
  assert.ok(token);

  const stolen = await accept(env, intruder, orgId, memberId, { token });
  assert.equal(stolen.status, 400);
  assert.equal(await errorMessage(stolen), 'User email does not match invite.');

  // The invitee's sync is cached by revision date, so accept must move it. Pin the clock past it so
  // the comparison cannot tie within a millisecond.
  const revisionBeforeAccept = await revisionDate(env, invitee);
  context.mock.timers.enable({ apis: ['Date'], now: revisionBeforeAccept + MS_PER_SECOND });
  assert.equal((await accept(env, invitee, orgId, memberId, { token })).status, 200);
  assert.ok((await revisionDate(env, invitee)) > revisionBeforeAccept, 'accept did not bump the invitee revision date');
  const accepted = await findMember(env, owner, orgId, invitee.email);
  assert.equal(accepted.status, MembershipStatus.Accepted);
  assert.equal(accepted.userId, invitee.id);

  const replayed = await accept(env, invitee, orgId, memberId, { token });
  assert.equal(replayed.status, 400);
  assert.equal(
    await errorMessage(replayed),
    'Invitation already accepted. You will receive an email when your organization membership is confirmed.',
  );

  // Official clients wrap the org key with the member's RSA public key (EncString types 3-6).
  // A type-2 key is wrapped with a symmetric key the member does not have.
  assert.equal((await confirm(env, owner, orgId, memberId, '2.a|b|c')).status, 400);
  assert.equal((await confirm(env, owner, orgId, memberId, MEMBER_KEY)).status, 200);
  assert.equal((await findMember(env, owner, orgId, invitee.email)).status, MembershipStatus.Confirmed);
});

test('an invite token is bound to its own row and expires, and a revoked invite cannot be accepted', async (context) => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const invitee = await seedMailableUser(env);
  const other = await seedMailableUser(env);
  const orgId = await createOrg(env, owner);

  await invite(env, owner, orgId, [invitee.email, other.email]);
  const tokenFor = (email: string) => inviteToken(capture.sent, email);
  const memberId = (await findMember(env, owner, orgId, invitee.email)).id;

  // Official web's accept page branches on upstream's distinct expiry message.
  context.mock.timers.enable({ apis: ['Date'], now: Date.now() + ORG_INVITE_TTL_DAYS * MS_PER_DAY + MS_PER_SECOND });
  const expired = await accept(env, invitee, orgId, memberId, { token: tokenFor(invitee.email) });
  assert.equal(expired.status, 400);
  assert.equal(await errorMessage(expired), 'Expired token.');
  context.mock.timers.reset();

  const swapped = await accept(env, invitee, orgId, memberId, { token: tokenFor(other.email) });
  assert.equal(swapped.status, 400);
  assert.equal(await errorMessage(swapped), 'Invalid token.');

  const revoked = await authedFetch(env, { method: 'PUT', path: `/api/organizations/${orgId}/users/${memberId}/revoke`, userId: owner.id });
  assert.equal(revoked.status, 200);
  const afterRevoke = await accept(env, invitee, orgId, memberId, { token: tokenFor(invitee.email) });
  assert.equal(afterRevoke.status, 400);
  assert.equal(await errorMessage(afterRevoke), `Your access to the ${TEST_ORG_NAME} vault has been revoked.`);
});

test('a SCIM-provisioned existing account stays Invited and cannot be confirmed without accepting', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const victim = await seedUser(env);
  const orgId = await createOrg(env, owner);

  // Any org owner can mint a SCIM token, so SCIM must not bind the account either.
  await provisionViaScim(env, owner, orgId, victim.email);

  const member = await findMember(env, owner, orgId, victim.email);
  assert.equal(member.status, MembershipStatus.Invited);
  assert.equal(member.userId, null);
  const confirmed = await confirm(env, owner, orgId, member.id, MEMBER_KEY);
  assert.equal(confirmed.status, 400);
  assert.equal(await errorMessage(confirmed), 'User not valid.');
});

// Upstream PostUserCommand invites through the normal invite path, so the IdP-provisioned invitee
// gets the same emailed token that accept requires.
test('a SCIM-provisioned existing account is mailed an invite token that lets it accept', async () => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const invitee = await seedMailableUser(env);
  const orgId = await createOrg(env, owner);

  await provisionViaScim(env, owner, orgId, invitee.email);
  assert.deepEqual(capture.sent.map((message) => message.to), [invitee.email]);
  const params = inviteParams(capture.sent[0]);
  const memberId = (await findMember(env, owner, orgId, invitee.email)).id;
  assert.equal(params.get('organizationUserId'), memberId);
  assert.equal(params.get('orgUserHasExistingUser'), 'true');

  assert.equal((await accept(env, invitee, orgId, memberId, { token: params.get('token') })).status, 200);
  const accepted = await findMember(env, owner, orgId, invitee.email);
  assert.equal(accepted.status, MembershipStatus.Accepted);
  assert.equal(accepted.userId, invitee.id);
});

test('SCIM does not mail an address with no account, which stays staged', async () => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const email = `${crypto.randomUUID()}@${MAILABLE_DOMAIN}`;

  await provisionViaScim(env, owner, orgId, email);
  assert.deepEqual(capture.sent, []);
  assert.equal((await findMember(env, owner, orgId, email)).status, MembershipStatus.Staged);
});

// Upstream PostUserCommand answers 409 for a known member, so an IdP replaying a POST whose 201 was
// lost, or assigning the owner, sends no second invite and adds no duplicate row.
test('SCIM answers 409 for an address that is already a member and mails nothing', async () => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const invitee = await seedMailableUser(env);
  const orgId = await createOrg(env, owner);

  await provisionViaScim(env, owner, orgId, invitee.email);
  assert.equal((await postScimUser(env, owner, orgId, invitee.email.toUpperCase())).status, 409);
  assert.equal((await postScimUser(env, owner, orgId, owner.email)).status, 409);
  assert.equal(capture.sent.length, 1);
  assert.deepEqual((await listMembers(env, owner, orgId)).map((member) => member.email), [owner.email, invitee.email]);
});

// Upstream deletes the rows it saved when the send fails. IdPs retry a 5xx, so a kept row would
// multiply with every sync while the send keeps failing (suppressed recipient, unverified sender).
test('a failed invite send saves no member row, for member invite and SCIM', async () => {
  const env = await createTestEnv({
    ...captureEmail().overrides,
    EMAIL: { async send() { throw new Error('recipient suppressed'); } },
  });
  const owner = await seedUser(env);
  const invitee = await seedMailableUser(env);
  const orgId = await createOrg(env, owner);

  assert.equal((await postInvite(env, owner, orgId, [invitee.email])).status, 502);
  assert.equal((await postScimUser(env, owner, orgId, invitee.email)).status, 502);
  assert.equal((await postScimUser(env, owner, orgId, invitee.email)).status, 502);
  assert.deepEqual((await listMembers(env, owner, orgId)).map((member) => member.email), [owner.email]);
});

test('invite mail only links to a configured web vault and skips documentation addresses', async () => {
  const forwardedHeaders = { 'X-Forwarded-Host': FORWARDED_HOST, 'X-Forwarded-Proto': 'https' };

  // Without WEB_VAULT_ORIGINS the only candidate is the caller-controlled forwarded host.
  const unconfigured = captureEmail();
  const unconfiguredEnv = await createTestEnv({ ...unconfigured.overrides, WEB_VAULT_ORIGINS: '' });
  const unconfiguredOwner = await seedUser(unconfiguredEnv);
  const unconfiguredInvitee = await seedMailableUser(unconfiguredEnv);
  const unconfiguredOrgId = await createOrg(unconfiguredEnv, unconfiguredOwner);
  await invite(unconfiguredEnv, unconfiguredOwner, unconfiguredOrgId, [unconfiguredInvitee.email], forwardedHeaders);
  assert.deepEqual(unconfigured.sent, []);

  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const reserved = await seedUser(env);
  const invitee = await seedMailableUser(env);
  const orgId = await createOrg(env, owner);
  await invite(env, owner, orgId, [reserved.email, invitee.email], forwardedHeaders);
  assert.deepEqual(capture.sent.map((message) => message.to), [invitee.email]);
  inviteParams(capture.sent[0]);
  assert.equal((await findMember(env, owner, orgId, reserved.email)).status, MembershipStatus.Invited);
});

test('invite rejects an empty, oversized or malformed email list before saving or mailing anything', async () => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const tooMany = Array.from({ length: MAX_INVITE_EMAILS + 1 }, () => `${crypto.randomUUID()}@${MAILABLE_DOMAIN}`);
  const cases: Array<[string[], string]> = [
    [[], 'An email is required.'],
    [tooMany, `You can only submit up to ${MAX_INVITE_EMAILS} emails at a time.`],
    [[`ok@${MAILABLE_DOMAIN}`, 'foo@'], 'Email #2 is not valid.'],
    [[`${'a'.repeat(MAX_INVITE_EMAIL_LENGTH)}@${MAILABLE_DOMAIN}`], `Email #1 is longer than ${MAX_INVITE_EMAIL_LENGTH} characters.`],
  ];
  for (const [emails, expected] of cases) {
    const response = await postInvite(env, owner, orgId, emails);
    assert.equal(response.status, 400);
    assert.equal(await errorMessage(response), expected);
  }

  assert.deepEqual((await listMembers(env, owner, orgId)).map((member) => member.email), [owner.email]);
  assert.deepEqual(capture.sent, []);
});

test('invite mail defuses links and addresses hidden in the organization name', async () => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const invitee = await seedMailableUser(env);
  // Any user can create an org and name it, so the name is attacker text sent from EMAIL_FROM.
  const phishingName = `Vault locked, unlock at https://${FORWARDED_HOST}/x or mail a@${FORWARDED_HOST}`;
  const { id: orgId } = await createOwnedOrganization(env, owner, { name: phishingName, key: MEMBER_KEY });

  await invite(env, owner, orgId, [invitee.email]);
  const [sent] = capture.sent;
  assert.ok(sent);
  assert.equal(inviteParams(sent).get('organizationName'), phishingName);
  const textOutsideLink = String(sent.text).replace(INVITE_LINK_PATTERN, '');
  [sent.subject, textOutsideLink].forEach((text) => {
    assert.ok(!text.includes('://'), text);
    assert.ok(!text.includes(FORWARDED_HOST), text);
    assert.ok(!text.includes('@'), text);
  });
});

// The invite mail budget is a fixed window, so start on a boundary to keep every request inside one
// window. Returns the window length for tests that move past it.
function pinClockToInviteMailWindow(context: TestContext): number {
  const windowMs = LIMITS.rateLimit.orgInviteEmailWindowSeconds * MS_PER_SECOND;
  context.mock.timers.enable({ apis: ['Date'], now: Math.floor(Date.now() / windowMs) * windowMs });
  return windowMs;
}

// Any user can create an org and invite any address, so invite mail from EMAIL_FROM is budgeted per
// inviter across all of their orgs. A batch that would overrun the budget mails nothing and, like a
// failed send, saves no row.
test('invite mail is budgeted per inviter per hour, and a batch that overruns it gets 429 with nothing mailed or saved', async (context) => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const otherOrgId = await createOrg(env, owner);
  const budget = LIMITS.rateLimit.orgInviteEmailsPerHour;
  const windowSeconds = LIMITS.rateLimit.orgInviteEmailWindowSeconds;
  const addresses = (count: number) => Array.from({ length: count }, () => `${crypto.randomUUID()}@${MAILABLE_DOMAIN}`);
  const windowMs = pinClockToInviteMailWindow(context);

  for (let spent = 0; spent < budget - 1; spent += MAX_INVITE_EMAILS) {
    await invite(env, owner, orgId, addresses(Math.min(MAX_INVITE_EMAILS, budget - 1 - spent)));
  }
  assert.equal(capture.sent.length, budget - 1);

  const overrun = addresses(2);
  const blocked = await postInvite(env, owner, otherOrgId, overrun);
  assert.equal(blocked.status, 429);
  assert.equal(blocked.headers.get('Retry-After'), String(windowSeconds));
  assert.equal(await errorMessage(blocked), `Rate limit exceeded. Try again in ${windowSeconds} seconds.`);
  assert.equal(capture.sent.length, budget - 1);
  assert.deepEqual((await listMembers(env, owner, otherOrgId)).map((member) => member.email), [owner.email]);

  context.mock.timers.tick(windowMs);
  await invite(env, owner, otherOrgId, overrun);
  assert.deepEqual(capture.sent.slice(budget - 1).map((message) => message.to).sort(), [...overrun].sort());
});

// A SCIM token belongs to the org, so its directory spends the org's own budget rather than the
// owner's. Identity providers pace their retries by Retry-After, so the SCIM 429 carries it.
test('SCIM invite mail over its org budget gets a 429 SCIM error with Retry-After and saves no row', async (context) => {
  const capture = captureEmail();
  const env = await createTestEnv({ ...capture.overrides, EMAIL_SENDS_PER_HOUR: '1000' });
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const budget = LIMITS.rateLimit.orgInviteEmailsPerHour;
  const windowSeconds = LIMITS.rateLimit.orgInviteEmailWindowSeconds;
  pinClockToInviteMailWindow(context);

  for (let provisioned = 0; provisioned < budget; provisioned += 1) {
    await provisionViaScim(env, owner, orgId, (await seedMailableUser(env)).email);
  }
  const overrun = await seedMailableUser(env);
  const blocked = await postScimUser(env, owner, orgId, overrun.email);
  assert.equal(blocked.status, 429);
  assert.equal(blocked.headers.get('Retry-After'), String(windowSeconds));
  assert.deepEqual(await blocked.json(), {
    schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
    status: 429,
    detail: `Rate limit exceeded. Try again in ${windowSeconds} seconds.`,
  });
  assert.equal(capture.sent.length, budget);
  assert.ok(!(await listMembers(env, owner, orgId)).some((member) => member.email === overrun.email));

  // The directory spent none of the owner's own budget.
  await invite(env, owner, orgId, [overrun.email]);
  assert.equal(capture.sent.at(-1)?.to, overrun.email);
});

// Official web's accept page sends existing accounts to login and everyone else to signup.
test('one invite batch flags only the invitees that already have an account as existing users', async () => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const registered = await seedMailableUser(env);
  const unregistered = `${crypto.randomUUID()}@${MAILABLE_DOMAIN}`;
  const orgId = await createOrg(env, owner);

  await invite(env, owner, orgId, [registered.email, unregistered]);
  const existingFlags = Object.fromEntries(capture.sent.map((message) => [message.to, inviteParams(message).get('orgUserHasExistingUser')]));
  assert.deepEqual(existingFlags, { [registered.email]: 'true', [unregistered]: 'false' });
  assert.notEqual(capture.sent.find(({ to }) => to === registered.email)?.subject, capture.sent.find(({ to }) => to === unregistered)?.subject);
  for (const mail of capture.sent) {
    const claims = await verifyHs256Jwt(inviteParams(mail).get('token')!, env.JWT_SECRET);
    const displayedExpiry = mail.text.match(/This invitation expires on (.+)\./)?.[1];
    assert.ok(displayedExpiry);
    assert.equal(Date.parse(displayedExpiry), Number(claims?.exp) * 1000);
    assert.ok(mail.text.includes(`Invited by ${sanitizeForEmail(owner.email)}.`));
  }
});

test('SCIM invitation has no human inviter line', async () => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const user = await seedMailableUser(env);
  await provisionViaScim(env, owner, orgId, user.email);
  assert.equal(capture.sent.length, 1);
  assert.doesNotMatch(capture.sent[0].text, /Invited by|scim:/);
  assert.equal(inviteParams(capture.sent[0]).get('email'), user.email);
});

// Upstream InviteUsersAsync invites each distinct address once and skips any address already in the
// org, so a re-invite neither mails nor adds a second row that accept would refuse.
test('invite mails and saves an address listed twice in one request only once', async () => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const invitee = `${crypto.randomUUID()}@${MAILABLE_DOMAIN}`;
  const orgId = await createOrg(env, owner);

  await invite(env, owner, orgId, [invitee, invitee.toUpperCase()]);
  assert.deepEqual(capture.sent.map((message) => message.to), [invitee]);
  assert.deepEqual((await listMembers(env, owner, orgId)).map((member) => member.email), [owner.email, invitee]);
});

// Upstream SelectKnownEmailsAsync matches either the row's invited email or its bound account's
// email, which differ once the account changes its email.
test('invite skips addresses already in the org by invited or account email and answers 200 when none remain', async () => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedMailableUser(env);
  const pending = `${crypto.randomUUID()}@${MAILABLE_DOMAIN}`;
  const orgId = await createOrg(env, owner);
  await invite(env, owner, orgId, [pending]);
  const renamedOwner = { ...owner, email: `${crypto.randomUUID()}@${MAILABLE_DOMAIN}` };
  await env.DB.prepare('UPDATE users SET email = ? WHERE id = ?').bind(renamedOwner.email, owner.id).run();
  const revisionBeforeReinvite = await revisionDate(env, owner);

  await invite(env, owner, orgId, [pending.toUpperCase(), owner.email, renamedOwner.email]);
  assert.equal(await revisionDate(env, owner), revisionBeforeReinvite, 'an invite with nothing left to invite bumped member revisions');
  assert.deepEqual(capture.sent.map((message) => message.to), [pending]);
  assert.deepEqual((await listMembers(env, owner, orgId)).map((member) => member.email), [renamedOwner.email, pending]);
});

// Official web's bulk confirm dialog posts every selected Accepted member with the org key wrapped
// for that member's public key. Upstream BulkConfirm confirms each entry on its own; unlike upstream,
// which drops entries it will not confirm, every entry gets a result, so another org's member reads
// like an id that does not exist.
test('bulk confirm confirms each Accepted member of the org with an RSA-wrapped key and reports every other entry', async (context) => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const otherOrgId = await createOrg(env, owner);
  const { id: accepted, user: acceptedUser } = await acceptedMember(env, capture.sent, owner, orgId);
  const symmetricKeyed = (await acceptedMember(env, capture.sent, owner, orgId)).id;
  const invited = (await invitedMember(env, owner, orgId)).id;
  const foreign = (await acceptedMember(env, capture.sent, owner, otherOrgId)).id;
  const missing = crypto.randomUUID();

  // The member only receives the wrapped org key through a sync, which is cached by revision date,
  // so a confirm must move it and a batch that confirms nobody must not. Pin the clock past it so
  // the comparison cannot tie within a millisecond.
  const revisionBeforeConfirm = await revisionDate(env, acceptedUser);
  context.mock.timers.enable({ apis: ['Date'], now: revisionBeforeConfirm + MS_PER_SECOND });
  const confirmsNobody = await postBulk(env, owner, orgId, 'confirm', { keys: [{ id: missing, key: MEMBER_KEY }] });
  assert.deepEqual(await bulkErrors(confirmsNobody), [[missing, 'User not valid.']]);
  assert.equal(await revisionDate(env, acceptedUser), revisionBeforeConfirm, 'a bulk confirm that confirmed nobody bumped member revisions');

  const keys = [
    { id: accepted, key: MEMBER_KEY },
    { id: symmetricKeyed, key: '2.a|b|c' },
    { id: invited, key: MEMBER_KEY },
    { id: foreign, key: MEMBER_KEY },
    { id: missing, key: MEMBER_KEY },
  ];
  assert.deepEqual(await bulkErrors(await postBulk(env, owner, orgId, 'confirm', { keys })), [
    [accepted, ''],
    [symmetricKeyed, 'Key is not a valid encrypted string.'],
    [invited, 'User not valid.'],
    [foreign, 'User not valid.'],
    [missing, 'User not valid.'],
  ]);
  assert.ok((await revisionDate(env, acceptedUser)) > revisionBeforeConfirm, 'bulk confirm did not bump the confirmed member revision date');
  const statuses = await memberStatuses(env, owner, orgId);
  assert.equal(statuses[accepted], MembershipStatus.Confirmed);
  assert.equal((await orgRepo.getMembership(env.DB, accepted))?.key, MEMBER_KEY);
  assert.equal(statuses[symmetricKeyed], MembershipStatus.Accepted);
  assert.equal(statuses[invited], MembershipStatus.Invited);
  assert.equal((await memberStatuses(env, owner, otherOrgId))[foreign], MembershipStatus.Accepted);

  const keyless = await postBulk(env, owner, orgId, 'confirm', {});
  assert.equal(keyless.status, 400);
  assert.equal(await errorMessage(keyless), 'The Keys field is required.');
});

// Upstream ResendOrganizationInviteCommand. Invite tokens expire after ORG_INVITE_TTL_DAYS, and
// "Resend invitation" is the only way back short of deleting and re-inviting the member.
test('reinvite mails an Invited member a fresh token once the first has expired, and refuses every other row', async (context) => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const otherOrgId = await createOrg(env, owner);
  const invited = await invitedMember(env, owner, orgId);
  const expiredToken = inviteToken(capture.sent, invited.email);
  const ownerMemberId = (await findMember(env, owner, orgId, owner.email)).id;
  const invitee = await seedUser(env, { email: invited.email });

  context.mock.timers.enable({ apis: ['Date'], now: Date.now() + ORG_INVITE_TTL_DAYS * MS_PER_DAY + MS_PER_SECOND });
  const refusals: Array<[string, string]> = [[orgId, ownerMemberId], [otherOrgId, invited.id], [orgId, crypto.randomUUID()]];
  for (const [targetOrgId, memberId] of refusals) {
    const refused = await reinvite(env, owner, targetOrgId, memberId);
    assert.equal(refused.status, 400);
    assert.equal(await errorMessage(refused), 'User invalid.');
  }
  assert.equal(capture.sent.length, 1);

  assert.equal((await reinvite(env, owner, orgId, invited.id)).status, 200);
  assert.deepEqual(capture.sent.map((message) => message.to), [invited.email, invited.email]);
  const expired = await accept(env, invitee, orgId, invited.id, { token: expiredToken });
  assert.equal(await errorMessage(expired), 'Expired token.');
  assert.equal((await accept(env, invitee, orgId, invited.id, { token: inviteToken(capture.sent, invited.email) })).status, 200);

  const afterAccept = await reinvite(env, owner, orgId, invited.id);
  assert.equal(afterAccept.status, 400);
  assert.equal(await errorMessage(afterAccept), 'User invalid.');
  assert.equal(capture.sent.length, 2);
});

// Upstream BulkResendOrganizationInvitesCommand reports "User invalid." for a row that is not Invited
// or belongs to another org; unlike upstream, a missing id answers the same rather than dropping out.
// Official web sends up to 500 ids at once, more than one D1 statement can bind.
test('bulk reinvite mails only the Invited members of the org once each and reports every other id', async () => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const otherOrgId = await createOrg(env, owner);
  const [first, second] = [await invitedMember(env, owner, orgId), await invitedMember(env, owner, orgId)];
  const accepted = (await acceptedMember(env, capture.sent, owner, orgId)).id;
  const foreign = (await invitedMember(env, owner, otherOrgId)).id;
  const missing = Array.from({ length: D1_MAX_BOUND_PARAMETERS + 1 }, () => crypto.randomUUID());
  const mailedBefore = capture.sent.length;

  const ids = [first.id, second.id, second.id, accepted, foreign, ...missing];
  assert.deepEqual(await bulkErrors(await postBulk(env, owner, orgId, 'reinvite', { ids })), [
    [first.id, ''],
    [second.id, ''],
    ...[accepted, foreign, ...missing].map((id): [string, string] => [id, 'User invalid.']),
  ]);
  assert.deepEqual(capture.sent.slice(mailedBefore).map((message) => message.to).sort(), [first.email, second.email].sort());

  const empty = await postBulk(env, owner, orgId, 'reinvite', {});
  assert.equal(empty.status, 400);
  assert.equal(await errorMessage(empty), "The field Ids must be a string or array type with a minimum length of '1'.");
});

// Reinvite mails from EMAIL_FROM like invite, so it spends the same per-inviter budget, and a bulk
// resend that would overrun it mails nothing.
test('reinvite spends the inviter mail budget, and a resend over it gets 429 with nothing mailed', async (context) => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const budget = LIMITS.rateLimit.orgInviteEmailsPerHour;
  const windowSeconds = String(LIMITS.rateLimit.orgInviteEmailWindowSeconds);
  pinClockToInviteMailWindow(context);

  for (let spent = 0; spent < budget - 1; spent += MAX_INVITE_EMAILS) {
    const count = Math.min(MAX_INVITE_EMAILS, budget - 1 - spent);
    await invite(env, owner, orgId, Array.from({ length: count }, () => `${crypto.randomUUID()}@${MAILABLE_DOMAIN}`));
  }
  const [first, second] = (await listMembers(env, owner, orgId)).filter(({ status }) => status === MembershipStatus.Invited);

  const bulkBlocked = await postBulk(env, owner, orgId, 'reinvite', { ids: [first.id, second.id] });
  assert.equal(bulkBlocked.status, 429);
  assert.equal(bulkBlocked.headers.get('Retry-After'), windowSeconds);
  assert.equal(capture.sent.length, budget - 1);

  assert.equal((await reinvite(env, owner, orgId, first.id)).status, 200);
  const blocked = await reinvite(env, owner, orgId, second.id);
  assert.equal(blocked.status, 429);
  assert.equal(blocked.headers.get('Retry-After'), windowSeconds);
  assert.equal(capture.sent.length, budget);
});

// A plain member holds the org key, so without the manageUsers guard it could confirm any Accepted
// member, and it could spend the org's invite mail on resends.
test('bulk confirm and reinvite refuse a member without manageUsers, confirming and mailing nothing', async () => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const plainMember = await acceptedMember(env, capture.sent, owner, orgId);
  assert.equal((await confirm(env, owner, orgId, plainMember.id, MEMBER_KEY)).status, 200);
  const accepted = (await acceptedMember(env, capture.sent, owner, orgId)).id;
  const invited = (await invitedMember(env, owner, orgId)).id;
  const mailedBefore = capture.sent.length;

  const refusals = [
    await postBulk(env, plainMember.user, orgId, 'confirm', { keys: [{ id: accepted, key: MEMBER_KEY }] }),
    await reinvite(env, plainMember.user, orgId, invited),
    await postBulk(env, plainMember.user, orgId, 'reinvite', { ids: [invited] }),
  ];
  assert.deepEqual(refusals.map(({ status }) => status), [403, 403, 403]);
  assert.equal((await memberStatuses(env, owner, orgId))[accepted], MembershipStatus.Accepted);
  assert.equal(capture.sent.length, mailedBefore);
});

test('a malformed SCIM user payload gets a 400 SCIM error and saves no row', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const rejected = await postScimUser(env, owner, orgId, '', { userName: 42 });
  assert.equal(rejected.status, 400);
  const error = await rejected.json() as { schemas: string[]; status: number };
  assert.deepEqual([error.schemas, error.status], [['urn:ietf:params:scim:api:messages:2.0:Error'], 400]);
  assert.deepEqual((await listMembers(env, owner, orgId)).map((member) => member.email), [owner.email]);
});
