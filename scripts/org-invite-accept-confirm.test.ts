import assert from 'node:assert/strict';
import test from 'node:test';

import { createOwnedOrganization } from '../src/handlers/organizations';
import { MembershipStatus } from '../src/services/org-types';
import type { Env, User } from '../src/types';
import { ORG_INVITE_TTL_DAYS } from '../src/utils/jwt';
import { authedFetch, createTestEnv, seedUser } from './support/env';

// Upstream OrganizationService always stores invites as Invited with no user, and only
// AcceptOrgUserCommand (after checking the emailed token) binds the user. Without that, anyone can
// invite and confirm an existing account and push their org policies onto it.
const ORG_NAME = 'Acme';
const OFFICIAL_WEB_ORIGIN = 'https://web.example.test';
const MEMBER_KEY = '4.dGVzdA==';
const INVITE_LINK_PATTERN = /https:\/\/\S+accept-organization\?\S+/;
// seedUser's example.test addresses are RFC 6761 names, which invites never mail.
const MAILABLE_DOMAIN = 'stevefan1999.tech';
const FORWARDED_HOST = 'evil.example';
// Upstream StrictEmailAddressListAttribute limits.
const MAX_INVITE_EMAILS = 20;
const MAX_INVITE_EMAIL_LENGTH = 256;
const MS_PER_SECOND = 1000;
const MS_PER_DAY = 24 * 60 * 60 * MS_PER_SECOND;

interface MemberBody {
  id: string;
  userId: string | null;
  name: string | null;
  email: string;
  status: number;
}

interface SentEmail {
  to: unknown;
  subject: string;
  text?: string;
}

function emailCapture(): { env: Partial<Env>; sent: SentEmail[] } {
  const sent: SentEmail[] = [];
  return {
    sent,
    env: {
      EMAIL: {
        async send(message) {
          sent.push(message);
          return { messageId: crypto.randomUUID() };
        },
      },
      EMAIL_FROM: 'noreply@nodewarden.test',
      WEB_VAULT_ORIGINS: OFFICIAL_WEB_ORIGIN,
    },
  };
}

// The official web /#/accept-organization route reads these query params (DirectOrganizationInvite).
function inviteParams(email: SentEmail): URLSearchParams {
  const link = email.text?.match(INVITE_LINK_PATTERN)?.[0];
  assert.ok(link, 'invite email has no accept-organization link');
  assert.ok(link.startsWith(`${OFFICIAL_WEB_ORIGIN}/#/accept-organization?`), link);
  return new URLSearchParams(link.slice(link.indexOf('?') + 1));
}

function seedMailableUser(env: Env): Promise<User> {
  return seedUser(env, { email: `${crypto.randomUUID()}@${MAILABLE_DOMAIN}` });
}

async function errorMessage(response: Response): Promise<string> {
  return ((await response.json()) as { error: string }).error;
}

async function createOrg(env: Env, owner: User): Promise<string> {
  return (await createOwnedOrganization(env, owner, { name: ORG_NAME, key: MEMBER_KEY })).id;
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

async function postScimUser(env: Env, owner: User, orgId: string, email: string): Promise<Response> {
  const scimKey = await authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/scim-key`, userId: owner.id });
  assert.equal(scimKey.status, 200);
  const { token } = await scimKey.json() as { token: string };
  return authedFetch(env, {
    method: 'POST',
    path: `/scim/v2/${orgId}/Users`,
    body: { userName: email },
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
  const capture = emailCapture();
  const env = await createTestEnv(capture.env);
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
  assert.equal(params.get('organizationName'), ORG_NAME);
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
  const capture = emailCapture();
  const env = await createTestEnv(capture.env);
  const owner = await seedUser(env);
  const invitee = await seedMailableUser(env);
  const other = await seedMailableUser(env);
  const orgId = await createOrg(env, owner);

  await invite(env, owner, orgId, [invitee.email, other.email]);
  const tokenFor = (email: string) => {
    const sent = capture.sent.find((message) => message.to === email);
    assert.ok(sent, `no invite email to ${email}`);
    return inviteParams(sent).get('token');
  };
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
  assert.equal(await errorMessage(afterRevoke), `Your access to the ${ORG_NAME} vault has been revoked.`);
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
  const capture = emailCapture();
  const env = await createTestEnv(capture.env);
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
  const capture = emailCapture();
  const env = await createTestEnv(capture.env);
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
  const capture = emailCapture();
  const env = await createTestEnv(capture.env);
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
    ...emailCapture().env,
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
  const unconfigured = emailCapture();
  const unconfiguredEnv = await createTestEnv({ ...unconfigured.env, WEB_VAULT_ORIGINS: '' });
  const unconfiguredOwner = await seedUser(unconfiguredEnv);
  const unconfiguredInvitee = await seedMailableUser(unconfiguredEnv);
  const unconfiguredOrgId = await createOrg(unconfiguredEnv, unconfiguredOwner);
  await invite(unconfiguredEnv, unconfiguredOwner, unconfiguredOrgId, [unconfiguredInvitee.email], forwardedHeaders);
  assert.deepEqual(unconfigured.sent, []);

  const capture = emailCapture();
  const env = await createTestEnv(capture.env);
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
  const capture = emailCapture();
  const env = await createTestEnv(capture.env);
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
  const capture = emailCapture();
  const env = await createTestEnv(capture.env);
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
