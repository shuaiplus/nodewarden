const EMPTY_FORMS_FILENAME = 'forms.v1.json';
const EMPTY_FORMS_SCHEMA_FILENAME = 'forms.v1.schema.json';
const EMPTY_FORMS_CID = 'sha256:189fa7c9bcf8951e65c18b5d9feacf74a5223c75e01667c4235388cbc67091fe';

const EMPTY_FORMS_BODY = JSON.stringify({
  schemaVersion: '1.0.0',
  hosts: {},
});

const EMPTY_FORMS_SCHEMA_BODY = JSON.stringify({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  title: 'Bitwarden Fill Assist Forms v1',
  type: 'object',
  required: ['schemaVersion', 'hosts'],
  properties: {
    schemaVersion: { type: 'string' },
    hosts: { type: 'object' },
  },
  additionalProperties: true,
});

const EMPTY_MANIFEST_BODY = JSON.stringify({
  buildId: 'nodewarden-empty-fill-assist-v1',
  timestamp: '2026-07-06T00:00:00.000Z',
  gitSha: 'nodewarden',
  maps: {
    forms: {
      v1: {
        filename: EMPTY_FORMS_FILENAME,
        cid: EMPTY_FORMS_CID,
        schema: EMPTY_FORMS_SCHEMA_FILENAME,
        deprecated: false,
      },
    },
  },
});

const DIGITAL_ASSET_LINK_CHECK_BODY = JSON.stringify({
  linked: false,
  maxAge: '86400s',
  debugString: 'No matching digital asset link policy is configured for this server.',
});

function fillAssistJsonResponse(body: string): Response {
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  });
}

function normalizeFilename(filename: string): string {
  const raw = String(filename || '').trim();
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

export function handleFillAssistManifest(): Response {
  return fillAssistJsonResponse(EMPTY_MANIFEST_BODY);
}

export function handleFillAssistForms(filename: string): Response {
  const normalized = normalizeFilename(filename);
  if (normalized === EMPTY_FORMS_FILENAME) {
    return fillAssistJsonResponse(EMPTY_FORMS_BODY);
  }
  if (normalized === EMPTY_FORMS_SCHEMA_FILENAME) {
    return fillAssistJsonResponse(EMPTY_FORMS_SCHEMA_BODY);
  }
  return new Response('Not found', { status: 404 });
}

export function handleDigitalAssetLinkCheck(): Response {
  return fillAssistJsonResponse(DIGITAL_ASSET_LINK_CHECK_BODY);
}
