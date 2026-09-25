import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ENTERPRISE_PLAN_TYPE,
  buildNodeWardenEnterpriseLicense,
  parseOrganizationLicense,
} from './enterprise-license';

test('parses an official organization license file', () => {
  const parsed = parseOrganizationLicense({
    Name: 'Acme',
    BillingEmail: 'billing@acme.test',
    PlanType: 20,
  }, 'Fallback');
  assert.equal(parsed.name, 'Acme');
  assert.equal(parsed.billingEmail, 'billing@acme.test');
  assert.equal(parsed.planType, 20);
});

test('accepts a dummy or empty license as Enterprise', () => {
  const parsed = parseOrganizationLicense({}, 'NodeWarden');
  assert.equal(parsed.name, 'NodeWarden');
  assert.equal(parsed.planType, ENTERPRISE_PLAN_TYPE);
});

test('ships a self-host enterprise license the official web can upload', () => {
  const license = buildNodeWardenEnterpriseLicense({ name: 'HQ', billingEmail: 'owner@example.com' });
  assert.equal(license.selfHost, true);
  assert.equal(license.planType, ENTERPRISE_PLAN_TYPE);
  assert.equal(license.useResetPassword, true);
  assert.equal(license.usersGetPremium, true);
});
