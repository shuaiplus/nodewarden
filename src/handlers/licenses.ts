import { z } from 'zod';
import type { Env, User } from '../types';
import { errorResponse, jsonResponse, parseBody } from '../utils/response';
import { organizationResponse } from '../utils/org-response';
import { buildNodeWardenEnterpriseLicense, parseOrganizationLicense } from '../services/enterprise-license';
import { createOwnedOrganization } from './organizations';
import * as orgRepo from '../services/storage-org-repo';
import { canDeleteOrganization, isActiveMember } from '../services/org-authz';
import { jsonText } from '../services/org-types';

// A JSON body is the license itself unless it nests one under license.
const LicenseJsonRequest = z.looseObject({ key: z.string().nullish(), collectionName: z.string().nullish() });

async function readOrgLicenseForm(request: Request): Promise<{ license: unknown; key: string; collectionName: string } | Response> {
  const contentType = String(request.headers.get('Content-Type') || '');
  if (contentType.includes('multipart/form-data') || contentType.includes('application/x-www-form-urlencoded')) {
    const form = await request.formData();
    // The Workers FormData types omit the File entries a multipart upload carries.
    const licenseField = (form.get('license') ?? form.get('License')) as Blob | string | null;
    const text = typeof licenseField === 'string' ? licenseField : await licenseField?.text() ?? '';
    // Text that is not JSON is the organization's name when posted as a field, and 'Organization' when uploaded as a file.
    const unparsed = { name: typeof licenseField === 'string' ? text : 'Organization' };
    return {
      license: text.trim() ? jsonText.catch(unparsed).parse(text) : {},
      key: String(form.get('key') || form.get('Key') || ''),
      collectionName: String(form.get('collectionName') || form.get('CollectionName') || 'Default Collection'),
    };
  }
  const body = await parseBody(request, LicenseJsonRequest);
  if (body instanceof Response) return body;
  return {
    license: body.license || body,
    key: body.key || '',
    collectionName: body.collectionName || 'Default Collection',
  };
}

export function enterpriseLicenseFileResponse(user: User): Response {
  const license = buildNodeWardenEnterpriseLicense({ name: user.name || 'NodeWarden Enterprise', billingEmail: user.email });
  return new Response(JSON.stringify(license, null, 2), {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': 'attachment; filename="bitwarden_organization_license.json"',
      'Cache-Control': 'no-store',
    },
  });
}

export async function handleCreateSelfHostedOrganizationLicense(request: Request, env: Env, user: User): Promise<Response> {
  const form = await readOrgLicenseForm(request);
  if (form instanceof Response) return form;
  if (!form.key) return errorResponse('Organization key is required', 400);
  const parsed = parseOrganizationLicense(form.license, user.name || 'Organization');
  const org = await createOwnedOrganization(env, user, {
    name: parsed.name,
    billingEmail: parsed.billingEmail || user.email,
    collectionName: form.collectionName || 'Default Collection',
    key: form.key,
  });
  return jsonResponse(organizationResponse(org));
}

// The uploaded license changes nothing, since every organization runs as Enterprise, so its body is never read.
export async function handleUpdateSelfHostedOrganizationLicense(
  _request: Request,
  env: Env,
  user: User,
  orgId: string
): Promise<Response> {
  const member = await orgRepo.getMembershipByUserAndOrg(env.DB, user.id, orgId);
  if (!isActiveMember(member) || !canDeleteOrganization(member)) {
    return errorResponse('Organization not found', 404);
  }
  const org = await orgRepo.getOrganization(env.DB, orgId);
  if (!org) return errorResponse('Organization not found', 404);
  return jsonResponse(organizationResponse(org));
}

export async function handleSyncSelfHostedOrganizationLicense(
  env: Env,
  user: User,
  orgId: string
): Promise<Response> {
  const member = await orgRepo.getMembershipByUserAndOrg(env.DB, user.id, orgId);
  if (!isActiveMember(member) || !canDeleteOrganization(member)) {
    return errorResponse('Organization not found', 404);
  }
  const org = await orgRepo.getOrganization(env.DB, orgId);
  if (!org) return errorResponse('Organization not found', 404);
  return jsonResponse(organizationResponse(org));
}

export async function handleAccountLicenseUpload(): Promise<Response> {
  return new Response(null, { status: 200 });
}
