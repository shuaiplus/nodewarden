const OFFICIAL_DESKTOP_ORIGIN = 'bw-desktop-file://bundle';

function safeDecodeURIComponent(value) {
  let decoded = String(value || '');
  for (let index = 0; index < 2 && /%[0-9a-f]{2}/i.test(decoded); index += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch (_error) {
      break;
    }
  }
  return decoded;
}

export function decodeBase64Utf8(value) {
  let normalized = String(value || '').replace(/ /g, '+').replace(/-/g, '+').replace(/_/g, '/');
  normalized += '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  let binary;
  try {
    binary = atob(normalized);
  } catch (_error) {
    throw new Error('Cannot parse WebAuthn data.');
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (typeof TextDecoder !== 'undefined') return new TextDecoder().decode(bytes);
  return decodeURIComponent(Array.from(bytes, (byte) => `%${byte.toString(16).padStart(2, '0')}`).join(''));
}

export function bytesFromBase64Url(value) {
  let normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  normalized += '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  try {
    return Uint8Array.from(atob(normalized), (character) => character.charCodeAt(0));
  } catch (_error) {
    throw new Error('Cannot parse WebAuthn data.');
  }
}

export function base64UrlFromBuffer(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = '';
  for (let index = 0; index < bytes.length; index += 1) binary += String.fromCharCode(bytes[index]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function parseConnectorRequest(search) {
  const params = search instanceof URLSearchParams
    ? search
    : new URLSearchParams(String(search || '').replace(/^\?/, ''));
  const parentUrl = safeDecodeURIComponent(params.get('parent'));
  const encodedData = params.get('data');
  if (!parentUrl) throw new Error('No parent.');
  if (!encodedData) throw new Error('No data.');

  let parsedParent;
  try {
    parsedParent = new URL(parentUrl);
  } catch (_error) {
    throw new Error('Invalid parent.');
  }

  let webauthnJson;
  if (params.get('v') === '1') {
    webauthnJson = decodeBase64Utf8(encodedData);
  } else {
    let payload;
    try {
      payload = JSON.parse(decodeBase64Utf8(encodedData));
    } catch (_error) {
      throw new Error('Cannot parse data.');
    }
    if (!payload || (typeof payload.data !== 'string' && typeof payload.data !== 'object')) {
      throw new Error('Cannot parse data.');
    }
    webauthnJson = typeof payload.data === 'string' ? payload.data : JSON.stringify(payload.data);
  }

  return {
    parentUrl,
    parentProtocol: parsedParent.protocol.toLowerCase(),
    parentOrigin: parsedParent.origin,
    webauthnJson,
    buttonText: safeDecodeURIComponent(params.get('btnText')),
    awaitingText: safeDecodeURIComponent(params.get('btnAwaitingInteractionText')),
  };
}

export function normalizePublicKeyOptions(webauthnJson) {
  const source = typeof webauthnJson === 'string' ? JSON.parse(webauthnJson) : webauthnJson;
  if (!source || typeof source !== 'object' || !source.challenge) throw new Error('Cannot parse WebAuthn data.');
  const publicKey = { ...source, challenge: bytesFromBase64Url(source.challenge) };
  if (Array.isArray(source.allowCredentials)) {
    publicKey.allowCredentials = source.allowCredentials.map((credential) => ({
      ...credential,
      id: bytesFromBase64Url(credential?.id),
    }));
  }
  return publicKey;
}

export function buildCredentialData(assertedCredential) {
  const response = assertedCredential?.response;
  if (!assertedCredential || !response?.authenticatorData || !response?.clientDataJSON || !response?.signature) {
    throw new Error('The authenticator returned an incomplete response.');
  }
  return JSON.stringify({
    id: assertedCredential.id,
    rawId: base64UrlFromBuffer(assertedCredential.rawId),
    type: assertedCredential.type,
    extensions: typeof assertedCredential.getClientExtensionResults === 'function'
      ? assertedCredential.getClientExtensionResults()
      : {},
    response: {
      authenticatorData: base64UrlFromBuffer(response.authenticatorData),
      clientDataJson: base64UrlFromBuffer(response.clientDataJSON),
      signature: base64UrlFromBuffer(response.signature),
    },
  });
}

function normalizeAllowedOrigin(value) {
  try {
    const url = new URL(String(value || ''));
    return url.protocol && url.host ? `${url.protocol}//${url.host}` : '';
  } catch (_error) {
    return '';
  }
}

function isExtensionOrigin(origin) {
  return origin.startsWith('chrome-extension://')
    || origin.startsWith('moz-extension://')
    || origin.startsWith('safari-web-extension://');
}

export function resolveParentChannel(request, connectorOrigin, allowedOrigins = []) {
  if (request.parentProtocol === 'file:') {
    return { eventOrigin: 'null', targetOrigin: request.parentUrl };
  }

  const parentOrigin = normalizeAllowedOrigin(request.parentUrl);
  if (!parentOrigin) throw new Error('Invalid parent.');
  if (parentOrigin === connectorOrigin) {
    return { eventOrigin: parentOrigin, targetOrigin: parentOrigin };
  }
  if (parentOrigin === OFFICIAL_DESKTOP_ORIGIN) {
    return { eventOrigin: parentOrigin, targetOrigin: request.parentUrl };
  }
  const trustedOrigins = allowedOrigins.map(normalizeAllowedOrigin).filter(Boolean);
  if (isExtensionOrigin(parentOrigin) && trustedOrigins.includes(parentOrigin)) {
    return { eventOrigin: parentOrigin, targetOrigin: parentOrigin };
  }
  throw new Error('Untrusted parent.');
}

async function loadAllowedParentOrigins() {
  try {
    const response = await fetch('/api/web-bootstrap', {
      headers: { Accept: 'application/json' },
      credentials: 'omit',
    });
    if (!response.ok) return [];
    const body = await response.json();
    return Array.isArray(body?.webAuthnAllowedOrigins) ? body.webAuthnAllowedOrigins : [];
  } catch (_error) {
    return [];
  }
}

function browserErrorMessage(error) {
  return error?.message || String(error || 'WebAuthn failed.');
}

async function initializePage() {
  const button = document.getElementById('webauthn-button');
  if (!button) return;

  let request;
  let publicKey;
  let channel;
  let stopWebAuthn = false;
  let sentSuccess = false;
  let running = false;

  const defaultText = 'Read security key';
  const awaitingDefaultText = 'Awaiting security key interaction...';

  function setButton(awaiting = false) {
    button.textContent = awaiting
      ? request?.awaitingText || awaitingDefaultText
      : request?.buttonText || defaultText;
    button.setAttribute('aria-disabled', awaiting ? 'true' : 'false');
    button.setAttribute('aria-busy', awaiting ? 'true' : 'false');
    button.onclick = awaiting ? null : executeWebAuthn;
  }

  function post(message) {
    window.parent.postMessage(message, channel.targetOrigin);
  }

  function reportError(error) {
    if (channel) post(`error|${browserErrorMessage(error)}`);
    setButton(false);
  }

  async function executeWebAuthn() {
    if (running || sentSuccess) return;
    if (stopWebAuthn) {
      stopWebAuthn = false;
      setButton(false);
      return;
    }
    running = true;
    setButton(true);
    try {
      const credential = await navigator.credentials.get({ publicKey });
      if (!credential) throw new Error('No security key was selected.');
      if (sentSuccess) return;
      post(`success|${buildCredentialData(credential)}`);
      sentSuccess = true;
    } catch (error) {
      reportError(error);
    } finally {
      running = false;
    }
  }

  try {
    request = parseConnectorRequest(window.location.search);
    publicKey = normalizePublicKeyOptions(request.webauthnJson);
    channel = resolveParentChannel(request, window.location.origin, await loadAllowedParentOrigins());
    setButton(false);
  } catch (error) {
    button.textContent = browserErrorMessage(error);
    button.setAttribute('aria-disabled', 'true');
    return;
  }

  if (!navigator.credentials || typeof navigator.credentials.get !== 'function' || !window.PublicKeyCredential) {
    reportError(new Error('WebAuthn is not supported in this browser.'));
    return;
  }

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent || event.origin !== channel.eventOrigin) return;
    if (event.data === 'stop') {
      stopWebAuthn = true;
      setButton(false);
    } else if (event.data === 'start' && stopWebAuthn) {
      stopWebAuthn = false;
      void executeWebAuthn();
    }
  });

  post('info|ready');
  const isSafari = navigator.userAgent.includes(' Safari/') && !navigator.userAgent.includes('Chrome');
  if (!isSafari) void executeWebAuthn();
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => void initializePage(), { once: true });
  } else {
    void initializePage();
  }
}
