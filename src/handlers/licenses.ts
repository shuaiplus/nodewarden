import type { Env, User } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import { organizationResponse } from '../utils/org-response';
import { buildNodeWardenEnterpriseLicense, parseOrganizationLicense } from '../services/enterprise-license';
import { createOwnedOrganization } from './organizations';
import * as orgRepo from '../services/storage-org-repo';
import { canDeleteOrganization, isActiveMember } from '../services/org-authz';

async function readLicenseFromRequest(request: Request): Promise<unknown> {
  const contentType = String(request.headers.get('Content-Type') || '');
  if (contentType.includes('multipart/form-data') || contentType.includes('application/x-www-form-urlencoded')) {
    const form = await request.formData();
    const license = form.get('license') ?? form.get('License');
    if (typeof license === 'string' && license.trim()) {
      try { return JSON.parse(license); } catch { return { name: license }; }
    }
    if (license && typeof license === 'object' && 'text' in license) {
      const text = await (license as Blob).text();
      if (!text.trim()) return {};
      try { return JSON.parse(text); } catch { return { name: 'Organization' }; }
    }
    return {
      key: String(form.get('key') || form.get('Key') || ''),
      collectionName: String(form.get('collectionName') || form.get('CollectionName') || ''),
    };
  }
  try {
    return await request.json();
  } catch {
    return {};
  }
}

async function readOrgLicenseForm(request: Request): Promise<{ license: unknown; key: string; collectionName: string }> {
  const contentType = String(request.headers.get('Content-Type') || '');
  if (contentType.includes('multipart/form-data') || contentType.includes('application/x-www-form-urlencoded')) {
    const form = await request.formData();
    const licenseField = form.get('license') ?? form.get('License');
    let license: unknown = {};
    if (typeof licenseField === 'string' && licenseField.trim()) {
      try { license = JSON.parse(licenseField); } catch { license = { name: licenseField }; }
    } else if (licenseField && typeof licenseField === 'object' && 'text' in licenseField) {
      const text = await (licenseField as Blob).text();
      if (text.trim()) {
        try { license = JSON.parse(text); } catch { license = { name: 'Organization' }; }
      }
    }
    return {
      license,
      key: String(form.get('key') || form.get('Key') || ''),
      collectionName: String(form.get('collectionName') || form.get('CollectionName') || 'Default Collection'),
    };
  }
  const body = await request.json() as Record<string, unknown>;
  return {
    license: body.license || body,
    key: String(body.key || ''),
    collectionName: String(body.collectionName || 'Default Collection'),
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

export async function handleUpdateSelfHostedOrganizationLicense(
  request: Request,
  env: Env,
  user: User,
  orgId: string
): Promise<Response> {
  const member = await orgRepo.getMembershipByUserAndOrg(env.DB, user.id, orgId);
  if (!isActiveMember(member) || !canDeleteOrganization(member)) {
    return errorResponse('Organization not found', 404);
  }
  await readLicenseFromRequest(request);
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
