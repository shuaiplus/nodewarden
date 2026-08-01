const CUSTOM_SCHEME_CALLBACK = 'bitwarden://webauthn-callback';
const APP_LINK_HOSTS = ['bitwarden.com', 'bitwarden.eu', 'bitwarden.pw', 'bitwarden-gov.com'];

function safeDecodeURIComponent(value) {
  let decoded = String(value || '');
  for (let index = 0; index < 2 && /%[0-9a-f]{2}/i.test(decoded); index += 1) {
    try {
      decoded = decodeURIComponent(decoded);
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
    throw new Error('The WebAuthn challenge is not valid Base64.');
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
    throw new Error('The WebAuthn challenge contains invalid binary data.');
  }
}

export function base64UrlFromBuffer(value) {
  if (value == null) return undefined;
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = '';
  for (let index = 0; index < bytes.length; index += 1) binary += String.fromCharCode(bytes[index]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function officialAppLinkHost(hostname) {
  const normalized = String(hostname || '').toLowerCase();
  return APP_LINK_HOSTS.find((host) => normalized === host || normalized.endsWith(`.${host}`)) || 'bitwarden.com';
}

export function resolveMobileCallbackUri({ deeplinkScheme, payload, hostname, legacyMobile = false }) {
  // Match Bitwarden's connector protocol: the scheme parameter governs the
  // callback shape. Any non-HTTPS scheme resolves to Bitwarden's fixed custom
  // scheme; a client-provided callbackUri is only a mobile-flow signal.
  if (deeplinkScheme) {
    return String(deeplinkScheme).toLowerCase() === 'https'
      ? `https://${officialAppLinkHost(hostname)}/webauthn-callback`
      : CUSTOM_SCHEME_CALLBACK;
  }
  return payload?.mobile === true || payload?.callbackUri != null || legacyMobile
    ? CUSTOM_SCHEME_CALLBACK
    : null;
}

export function parseConnectorRequest(search, hostname = '') {
  const params = search instanceof URLSearchParams
    ? search
    : new URLSearchParams(String(search || '').replace(/^\?/, ''));
  const encodedData = params.get('data');
  if (!encodedData) throw new Error('No WebAuthn challenge was provided.');

  const version = params.get('v');
  let payload = null;
  let webauthnJson;
  let headerText;
  let buttonText;
  let returnButtonText;
  let awaitingText;

  if (version === '1') {
    webauthnJson = decodeBase64Utf8(encodedData);
    headerText = params.get('headerText');
    buttonText = params.get('btnText');
    returnButtonText = params.get('btnReturnText');
    awaitingText = params.get('btnAwaitingInteractionText');
  } else {
    try {
      payload = JSON.parse(decodeBase64Utf8(encodedData));
    } catch (_error) {
      throw new Error('The WebAuthn challenge could not be decoded.');
    }
    if (!payload || (typeof payload.data !== 'string' && typeof payload.data !== 'object')) {
      throw new Error('The WebAuthn challenge is incomplete.');
    }
    webauthnJson = typeof payload.data === 'string' ? payload.data : JSON.stringify(payload.data);
    headerText = payload.headerText;
    buttonText = payload.btnText;
    returnButtonText = payload.btnReturnText;
    awaitingText = payload.btnAwaitingInteractionText;
  }

  const callbackUri = resolveMobileCallbackUri({
    deeplinkScheme: params.get('deeplinkScheme'),
    payload,
    hostname,
    legacyMobile: params.get('client') === 'mobile',
  });
  if (!callbackUri) throw new Error('No supported mobile return target was provided.');

  return {
    callbackUri,
    webauthnJson,
    headerText: safeDecodeURIComponent(headerText),
    buttonText: safeDecodeURIComponent(buttonText),
    returnButtonText: safeDecodeURIComponent(returnButtonText),
    awaitingText: safeDecodeURIComponent(awaitingText),
  };
}

export function normalizePublicKeyOptions(webauthnJson) {
  const source = typeof webauthnJson === 'string' ? JSON.parse(webauthnJson) : webauthnJson;
  if (!source || typeof source !== 'object' || !source.challenge) {
    throw new Error('The WebAuthn challenge is invalid.');
  }
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
  const extensions = typeof assertedCredential.getClientExtensionResults === 'function'
    ? assertedCredential.getClientExtensionResults()
    : {};
  const clientData = base64UrlFromBuffer(response.clientDataJSON);
  return JSON.stringify({
    id: assertedCredential.id,
    rawId: base64UrlFromBuffer(assertedCredential.rawId),
    type: assertedCredential.type,
    extensions,
    response: {
      authenticatorData: base64UrlFromBuffer(response.authenticatorData),
      clientDataJson: clientData,
      signature: base64UrlFromBuffer(response.signature),
    },
  });
}

export function buildCallbackUrl(callbackUri, key, value) {
  const separator = String(callbackUri).includes('?') ? '&' : '?';
  return `${callbackUri}${separator}${encodeURIComponent(key)}=${encodeURIComponent(String(value || ''))}`;
}

function translations(locale) {
  const normalized = String(locale || 'en').toLowerCase();
  if (normalized.startsWith('zh-tw') || normalized.startsWith('zh-hk')) {
    return {
      title: '兩步驟驗證', copy: '使用通行密鑰或安全金鑰完成登入。', button: '使用通行密鑰驗證',
      awaiting: '請依照系統提示完成驗證…', returning: '正在返回 Bitwarden…', returnButton: '返回 Bitwarden',
      unsupported: '此瀏覽器不支援通行密鑰。', cancelled: '驗證已取消，請重試。',
    };
  }
  if (normalized.startsWith('zh')) {
    return {
      title: '两步验证', copy: '使用通行密钥或安全密钥完成登录。', button: '使用通行密钥验证',
      awaiting: '请按照系统提示完成验证…', returning: '正在返回 Bitwarden…', returnButton: '返回 Bitwarden',
      unsupported: '此浏览器不支持通行密钥。', cancelled: '验证已取消，请重试。',
    };
  }
  return {
    title: 'Two-step verification', copy: 'Use your passkey or security key to finish signing in.',
    button: 'Authenticate with passkey', awaiting: 'Follow the system prompt to continue…',
    returning: 'Returning to Bitwarden…', returnButton: 'Return to Bitwarden',
    unsupported: 'This browser does not support passkeys.', cancelled: 'Verification was cancelled. Please try again.',
  };
}

function browserErrorMessage(error, text) {
  if (error?.name === 'NotAllowedError' || error?.name === 'AbortError') return text.cancelled;
  return error?.message || String(error || 'WebAuthn failed.');
}

function initializePage() {
  const button = document.getElementById('webauthn-button');
  const header = document.getElementById('webauthn-header');
  const copy = document.getElementById('webauthn-copy');
  const status = document.getElementById('webauthn-status');
  if (!button || !header || !copy || !status) return;

  const text = translations(navigator.languages?.[0] || navigator.language);
  document.documentElement.lang = navigator.languages?.[0] || navigator.language || 'en';
  copy.textContent = text.copy;
  let request;
  let publicKey;
  let completed = false;
  let returnUri = '';

  function setButton(label, state, handler) {
    button.textContent = label;
    button.dataset.state = state;
    button.disabled = state === 'unavailable';
    button.setAttribute('aria-disabled', handler ? 'false' : 'true');
    button.setAttribute('aria-busy', state === 'waiting' ? 'true' : 'false');
    button.onclick = handler;
  }

  function setStatus(kind, message) {
    status.hidden = !message;
    status.dataset.kind = kind;
    status.textContent = message || '';
    status.className = message ? `msg show ${kind}` : 'msg';
  }

  function navigate(uri) {
    returnUri = uri;
    window.location.replace(uri);
    setButton(request?.returnButtonText || text.returnButton, 'return', () => window.location.replace(returnUri));
  }

  function handoffError(message) {
    setStatus('error', message);
    if (request?.callbackUri) navigate(buildCallbackUrl(request.callbackUri, 'error', message));
  }

  async function executeWebAuthn() {
    if (completed || button.dataset.state === 'waiting') return;
    setStatus('info', request.awaitingText || text.awaiting);
    setButton(request.awaitingText || text.awaiting, 'waiting', null);
    try {
      const credential = await navigator.credentials.get({ publicKey });
      if (!credential) throw new Error('No passkey was selected.');
      const data = buildCredentialData(credential);
      completed = true;
      setStatus('success', text.returning);
      navigate(buildCallbackUrl(request.callbackUri, 'data', data));
    } catch (error) {
      setButton(request.buttonText || text.button, 'ready', executeWebAuthn);
      handoffError(browserErrorMessage(error, text));
    }
  }

  try {
    request = parseConnectorRequest(window.location.search, window.location.hostname);
    publicKey = normalizePublicKeyOptions(request.webauthnJson);
    header.textContent = request.headerText || text.title;
    setButton(request.buttonText || text.button, 'ready', executeWebAuthn);
  } catch (error) {
    header.textContent = text.title;
    setStatus('error', browserErrorMessage(error, text));
    setButton(text.button, 'unavailable', null);
  }

  if (!navigator.credentials || typeof navigator.credentials.get !== 'function' || !window.PublicKeyCredential) {
    handoffError(text.unsupported);
    if (!request?.callbackUri) setButton(text.button, 'unavailable', null);
  }
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initializePage, { once: true });
  else initializePage();
}
