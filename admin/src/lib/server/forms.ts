import { error, fail, redirect, type RequestEvent } from '@sveltejs/kit';

import type { OrganizationDetail, UserDetail } from '../../../../src/admin/portal-contract';

// A missing or non-text field reads as empty, so it fails the check that uses it instead of the request.
export function formText(form: FormData, name: string): string {
  const value = form.get(name);
  return typeof value === 'string' ? value : '';
}

// URLs that only take a form post answer anything else with 405.
export function postOnly(event: RequestEvent): void {
  if (event.request.method !== 'POST') error(405, 'This method is not supported.');
}

export async function requireUser(event: RequestEvent, id: string): Promise<UserDetail> {
  const detail = await event.platform!.portal.userDetail(id);
  if (!detail) error(404, 'User not found.');
  return detail;
}

export async function requireOrganization(event: RequestEvent, id: string): Promise<OrganizationDetail> {
  const detail = await event.platform!.portal.organizationDetail(id);
  if (!detail) error(404, 'Organization not found.');
  return detail;
}

// Destructive actions need a recent sign-in, the typed confirmation and a share of the hourly budget.
// Returns the 400 to hand back when the confirmation does not match, or null to proceed.
export async function confirmSensitiveAction(event: RequestEvent, typed: string, expected: string, viewPath: string) {
  const check = await event.platform!.portal.checkSensitiveAction(event.locals.session!, typed, expected);
  if (check.kind === 'reauth') redirect(303, `/admin/login?returnUrl=${encodeURIComponent(viewPath)}&m=reauth`);
  if (check.kind === 'throttled') {
    event.locals.retryAfterSeconds = check.retryAfterSeconds;
    error(429, 'Try again later.');
  }
  return check.kind === 'mismatch' ? fail(400, { notice: 'The typed confirmation does not match.' }) : null;
}

// User actions confirm by retyping the address, compared without case or surrounding spaces.
export async function confirmUserAction(event: RequestEvent, detail: UserDetail, viewPath: string) {
  const typed = formText(await event.request.formData(), 'confirmation')
    .trim()
    .toLowerCase();
  return confirmSensitiveAction(event, typed, detail.email.toLowerCase(), viewPath);
}
