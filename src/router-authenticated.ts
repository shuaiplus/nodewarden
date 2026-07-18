import type { Env, User } from './types';
import { errorResponse, jsonResponse, unsupportedResponse } from './utils/response';
import {
  handleGetProfile,
  handleUpdateProfile,
  handleGetKeys,
  handleSetKeys,
  handleGetRevisionDate,
  handleVerifyPassword,
  handleChangePassword,
  handleSetVerifyDevices,
  handleGetTotpStatus,
  handleSetTotpStatus,
  handleGetTotpRecoveryCode,
  handleGetTwoFactorProviders,
  handleGetTwoFactorAuthenticator,
  handlePutTwoFactorAuthenticator,
  handleGetTwoFactorYubiKey,
  handlePutTwoFactorYubiKey,
  handlePutTwoFactorYubiKeyConfig,
  handleBootstrapTwoFactorYubiKeyConfig,
  handleGetDeviceVerificationSettings,
  handlePutDeviceVerificationSettings,
  handleDisableTwoFactorProvider,
  handleGetApiKey,
  handleRotateApiKey,
} from './handlers/accounts';
import {
  handleGetCiphers,
  handleGetCipher,
  handleCreateCipher,
  handleUpdateCipher,
  handleDeleteCipher,
  handleDeleteCipherCompat,
  handlePermanentDeleteCipher,
  handleRestoreCipher,
  handleBulkArchiveCiphers,
  handlePartialUpdateCipher,
  handleBulkUnarchiveCiphers,
  handleBulkMoveCiphers,
  handleBulkDeleteCiphers,
  handleBulkPermanentDeleteCiphers,
  handleBulkRestoreCiphers,
  handleArchiveCipher,
  handleUnarchiveCipher,
} from './handlers/ciphers';
import {
  handleGetFolders,
  handleGetFolder,
  handleCreateFolder,
  handleUpdateFolder,
  handleDeleteFolder,
  handleBulkDeleteFolders,
} from './handlers/folders';
import {
  handleGetSends,
  handleGetSend,
  handleCreateSend,
  handleCreateFileSendV2,
  handleGetSendFileUpload,
  handleUploadSendFile,
  handleUpdateSend,
  handleDeleteSend,
  handleBulkDeleteSends,
  handleRemoveSendPassword,
  handleRemoveSendAuth,
} from './handlers/sends';
import { handleSync } from './handlers/sync';
import { handleCiphersImport } from './handlers/import';
import {
  handleCreateAttachment,
  handleUploadAttachment,
  handleGetAttachment,
  handleUpdateAttachmentMetadata,
  handleDeleteAttachment,
} from './handlers/attachments';
import { handleAuthenticatedDeviceRoute } from './router-devices';
import { handleAdminRoute } from './router-admin';
import { handleGetDomains, handleUpdateDomains } from './handlers/domains';
import {
  handleCreateAccountPasskeyCredential,
  handleDeleteAccountPasskeyCredential,
  handleDeleteTwoFactorWebAuthn,
  handleGetAccountPasskeyAttestationOptions,
  handleGetAccountPasskeyCredentials,
  handleGetAccountPasskeyUpdateAssertionOptions,
  handleGetTwoFactorWebAuthn,
  handleGetTwoFactorWebAuthnChallenge,
  handlePutTwoFactorWebAuthn,
  handleUpdateAccountPasskeyEncryption,
} from './handlers/account-passkeys';
import {
  handleCreateAdminAuthRequest,
  handleGetAuthRequest,
  handleListAuthRequests,
  handleListPendingAuthRequests,
  handleUpdateAuthRequest,
} from './handlers/auth-requests';

export async function handleAuthenticatedRoute(
  request: Request,
  env: Env,
  userId: string,
  currentUser: User,
  path: string,
  method: string
): Promise<Response | null> {
  if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
    const blockedAccountPaths = new Set([
      '/api/accounts/set-password',
      '/api/accounts/delete',
      '/api/accounts/delete-account',
      '/api/accounts/delete-vault',
    ]);
    if (blockedAccountPaths.has(path)) {
      return errorResponse('Not implemented', 501);
    }
  }

  if ((path === '/api/accounts/kdf' || path === '/accounts/kdf') && (method === 'POST' || method === 'PUT')) {
    return unsupportedResponse('KDF changes are not supported by this server.');
  }

  const mailBackedAccountPaths = new Set([
    '/api/accounts/email-token',
    '/accounts/email-token',
    '/api/accounts/verify-email',
    '/accounts/verify-email',
    '/api/accounts/verify-email-token',
    '/accounts/verify-email-token',
    '/api/accounts/request-otp',
    '/accounts/request-otp',
    '/api/accounts/verify-otp',
    '/accounts/verify-otp',
  ]);
  if (mailBackedAccountPaths.has(path) && (method === 'POST' || method === 'PUT')) {
    return unsupportedResponse('Email delivery is not supported by this server.');
  }

  const emailTwoFactorPaths = new Set([
    '/api/two-factor/get-email',
    '/two-factor/get-email',
    '/api/two-factor/send-email',
    '/two-factor/send-email',
    '/api/two-factor/send-email-login',
    '/two-factor/send-email-login',
    '/api/two-factor/email',
    '/two-factor/email',
  ]);
  if (emailTwoFactorPaths.has(path) && (method === 'POST' || method === 'PUT' || method === 'DELETE')) {
    return unsupportedResponse('Email two-step login is not supported by this server.');
  }

  if (path === '/api/accounts/profile') {
    if (method === 'GET') return handleGetProfile(request, env, userId);
    if (method === 'PUT') return handleUpdateProfile(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if ((path === '/api/accounts/password' || path === '/api/accounts/change-password') && (method === 'POST' || method === 'PUT')) {
    return handleChangePassword(request, env, userId);
  }

  if (path === '/api/accounts/keys') {
    if (method === 'GET') return handleGetKeys(request, env, userId);
    if (method === 'POST') return handleSetKeys(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/accounts/totp') {
    if (method === 'GET') return handleGetTotpStatus(request, env, userId);
    if (method === 'PUT' || method === 'POST') return handleSetTotpStatus(request, env, userId);
    return null;
  }

  if ((path === '/api/accounts/totp/recovery-code' || path === '/api/two-factor/get-recover') && method === 'POST') {
    return handleGetTotpRecoveryCode(request, env, userId);
  }

  if (path === '/api/two-factor') {
    if (method === 'GET') return handleGetTwoFactorProviders(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/two-factor/get-authenticator' && method === 'POST') {
    return handleGetTwoFactorAuthenticator(request, env, userId);
  }

  if ((path === '/api/two-factor/get-yubikey' || path === '/api/two-factor/get-yubi-key') && method === 'POST') {
    return handleGetTwoFactorYubiKey(request, env, userId);
  }

  if (path === '/api/two-factor/get-device-verification-settings' && method === 'POST') {
    return handleGetDeviceVerificationSettings(request, env, userId);
  }

  if (path === '/api/two-factor/device-verification-settings') {
    if (method === 'PUT' || method === 'POST') return handlePutDeviceVerificationSettings(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/two-factor/get-webauthn' && method === 'POST') {
    return handleGetTwoFactorWebAuthn(request, env, userId, currentUser);
  }

  if (path === '/api/two-factor/get-webauthn-challenge' && method === 'POST') {
    return handleGetTwoFactorWebAuthnChallenge(request, env, userId, currentUser);
  }

  if (path === '/api/two-factor/authenticator') {
    if (method === 'PUT' || method === 'POST') return handlePutTwoFactorAuthenticator(request, env, userId);
    if (method === 'DELETE') return handleDisableTwoFactorProvider(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if ((path === '/api/two-factor/yubikey' || path === '/api/two-factor/yubi-key')) {
    if (method === 'PUT' || method === 'POST') return handlePutTwoFactorYubiKey(request, env, userId);
    if (method === 'DELETE') return handleDisableTwoFactorProvider(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/two-factor/webauthn') {
    if (method === 'PUT' || method === 'POST') return handlePutTwoFactorWebAuthn(request, env, userId, currentUser);
    if (method === 'DELETE') return handleDeleteTwoFactorWebAuthn(request, env, userId, currentUser);
    return errorResponse('Method not allowed', 405);
  }

  if ((path === '/api/two-factor/yubikey/config' || path === '/api/two-factor/yubi-key/config') && (method === 'PUT' || method === 'POST')) {
    return handlePutTwoFactorYubiKeyConfig(request, env, userId);
  }

  if ((path === '/api/two-factor/yubikey/bootstrap' || path === '/api/two-factor/yubi-key/bootstrap') && method === 'POST') {
    return handleBootstrapTwoFactorYubiKeyConfig(request, env, userId);
  }

  if (path === '/api/two-factor/disable' && (method === 'PUT' || method === 'POST')) {
    return handleDisableTwoFactorProvider(request, env, userId);
  }

  if (path === '/api/accounts/revision-date' && method === 'GET') {
    return handleGetRevisionDate(request, env, userId);
  }

  if (path === '/api/accounts/verify-password' && method === 'POST') {
    return handleVerifyPassword(request, env, userId);
  }

  if (path === '/api/accounts/verify-devices' && (method === 'PUT' || method === 'POST')) {
    return handleSetVerifyDevices(request, env, userId);
  }

  if ((path === '/api/accounts/api-key' || path === '/api/accounts/api_key') && method === 'POST') {
    return handleGetApiKey(request, env, userId);
  }

  if ((path === '/api/accounts/rotate-api-key' || path === '/api/accounts/rotate_api_key') && method === 'POST') {
    return handleRotateApiKey(request, env, userId);
  }

  if (path === '/api/webauthn' || path === '/webauthn') {
    if (method === 'GET') return handleGetAccountPasskeyCredentials(request, env, userId);
    if (method === 'POST') return handleCreateAccountPasskeyCredential(request, env, userId);
    if (method === 'PUT') return handleUpdateAccountPasskeyEncryption(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if ((path === '/api/webauthn/attestation-options' || path === '/webauthn/attestation-options') && method === 'POST') {
    return handleGetAccountPasskeyAttestationOptions(request, env, userId, currentUser);
  }

  if ((path === '/api/webauthn/assertion-options' || path === '/webauthn/assertion-options') && method === 'POST') {
    return handleGetAccountPasskeyUpdateAssertionOptions(request, env, userId, currentUser);
  }

  const accountPasskeyDeleteMatch =
    path.match(/^\/api\/webauthn\/([^/]+)\/delete$/i) ||
    path.match(/^\/webauthn\/([^/]+)\/delete$/i);
  if (accountPasskeyDeleteMatch && method === 'POST') {
    return handleDeleteAccountPasskeyCredential(request, env, userId, accountPasskeyDeleteMatch[1], currentUser);
  }

  if (path === '/api/sync' && method === 'GET') {
    return handleSync(request, env, userId);
  }

  if (path.startsWith('/notifications/')) {
    return errorResponse('Not found', 404);
  }

  if (path === '/api/ciphers' || path === '/api/ciphers/create') {
    if (method === 'GET') return handleGetCiphers(request, env, userId);
    if (method === 'POST') return handleCreateCipher(request, env, userId);
    return null;
  }

  if (path === '/api/ciphers/import' && method === 'POST') {
    return handleCiphersImport(request, env, userId);
  }

  if (path === '/api/ciphers/delete' && method === 'POST') {
    return handleBulkDeleteCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/delete-permanent' && method === 'POST') {
    return handleBulkPermanentDeleteCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/restore' && method === 'POST') {
    return handleBulkRestoreCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/archive' && (method === 'PUT' || method === 'POST')) {
    return handleBulkArchiveCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/unarchive' && (method === 'PUT' || method === 'POST')) {
    return handleBulkUnarchiveCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/move' && (method === 'POST' || method === 'PUT')) {
    return handleBulkMoveCiphers(request, env, userId);
  }

  const cipherMatch = path.match(/^\/api\/ciphers\/([a-f0-9-]+)(\/.*)?$/i);
  if (cipherMatch) {
    const cipherId = cipherMatch[1];
    const subPath = cipherMatch[2] || '';

    if (subPath === '' || subPath === '/') {
      if (method === 'GET') return handleGetCipher(request, env, userId, cipherId);
      if (method === 'PUT' || method === 'POST') return handleUpdateCipher(request, env, userId, cipherId);
      if (method === 'DELETE') return handleDeleteCipherCompat(request, env, userId, cipherId);
    }

    if (subPath === '/delete' && method === 'PUT') return handleDeleteCipher(request, env, userId, cipherId);
    if (subPath === '/delete' && method === 'DELETE') return handlePermanentDeleteCipher(request, env, userId, cipherId);
    if (subPath === '/restore' && method === 'PUT') return handleRestoreCipher(request, env, userId, cipherId);
    if (subPath === '/archive' && (method === 'PUT' || method === 'POST')) return handleArchiveCipher(request, env, userId, cipherId);
    if (subPath === '/unarchive' && (method === 'PUT' || method === 'POST')) return handleUnarchiveCipher(request, env, userId, cipherId);
    if (subPath === '/partial' && (method === 'PUT' || method === 'POST')) return handlePartialUpdateCipher(request, env, userId, cipherId);
    if (subPath === '/share' && method === 'POST') return handleGetCipher(request, env, userId, cipherId);
    if (subPath === '/details' && method === 'GET') return handleGetCipher(request, env, userId, cipherId);
    if (subPath === '/attachment/v2' && method === 'POST') return handleCreateAttachment(request, env, userId, cipherId);
    if (subPath === '/attachment' && method === 'POST') return handleCreateAttachment(request, env, userId, cipherId);

    const attachmentMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)$/i);
    if (attachmentMatch) {
      const attachmentId = attachmentMatch[1];
      if (method === 'POST' || method === 'PUT') return handleUploadAttachment(request, env, userId, cipherId, attachmentId);
      if (method === 'GET') return handleGetAttachment(request, env, userId, cipherId, attachmentId);
      if (method === 'DELETE') return handleDeleteAttachment(request, env, userId, cipherId, attachmentId);
    }

    const attachmentMetadataMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)\/metadata$/i);
    if (attachmentMetadataMatch && (method === 'POST' || method === 'PUT')) {
      return handleUpdateAttachmentMetadata(request, env, userId, cipherId, attachmentMetadataMatch[1]);
    }

    const attachmentDeleteMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)\/delete$/i);
    if (attachmentDeleteMatch && method === 'POST') {
      return handleDeleteAttachment(request, env, userId, cipherId, attachmentDeleteMatch[1]);
    }
  }

  if (path === '/api/folders') {
    if (method === 'GET') return handleGetFolders(request, env, userId);
    if (method === 'POST') return handleCreateFolder(request, env, userId);
    return null;
  }

  if (path === '/api/folders/delete' && method === 'POST') {
    return handleBulkDeleteFolders(request, env, userId);
  }

  const folderMatch = path.match(/^\/api\/folders\/([a-f0-9-]+)$/i);
  if (folderMatch) {
    const folderId = folderMatch[1];
    if (method === 'GET') return handleGetFolder(request, env, userId, folderId);
    if (method === 'PUT') return handleUpdateFolder(request, env, userId, folderId);
    if (method === 'DELETE') return handleDeleteFolder(request, env, userId, folderId);
  }

  if (path === '/api/auth-requests' || path === '/api/auth-requests/' || path === '/auth-requests' || path === '/auth-requests/') {
    if (method === 'GET') return handleListAuthRequests(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/auth-requests/pending' || path === '/auth-requests/pending') {
    if (method === 'GET') return handleListPendingAuthRequests(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/auth-requests/admin-request' || path === '/auth-requests/admin-request') {
    if (method === 'POST') return handleCreateAdminAuthRequest(request, env, userId, currentUser.email);
    return errorResponse('Method not allowed', 405);
  }

  const authRequestMatch = path.match(/^\/(?:api\/)?auth-requests\/([a-f0-9-]+)$/i);
  if (authRequestMatch) {
    if (method === 'GET') return handleGetAuthRequest(request, env, userId, authRequestMatch[1]);
    if (method === 'PUT') return handleUpdateAuthRequest(request, env, userId, authRequestMatch[1]);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/collections' || path.startsWith('/api/collections/')) {
    if (method === 'GET') {
      return jsonResponse({ data: [], object: 'list', continuationToken: null });
    }
    return null;
  }

  if (path === '/api/organizations' || path.startsWith('/api/organizations/')) {
    if (method === 'GET') {
      return jsonResponse({ data: [], object: 'list', continuationToken: null });
    }
    return null;
  }

  if (path === '/api/sends') {
    if (method === 'GET') return handleGetSends(request, env, userId);
    if (method === 'POST') return handleCreateSend(request, env, userId);
    return null;
  }

  if (path === '/api/sends/file/v2' && method === 'POST') {
    return handleCreateFileSendV2(request, env, userId);
  }

  if (path === '/api/sends/delete' && method === 'POST') {
    return handleBulkDeleteSends(request, env, userId);
  }

  const sendMatch = path.match(/^\/api\/sends\/([^/]+)(\/.*)?$/i);
  if (sendMatch) {
    const sendId = sendMatch[1];
    const subPath = sendMatch[2] || '';

    if (subPath === '' || subPath === '/') {
      if (method === 'GET') return handleGetSend(request, env, userId, sendId);
      if (method === 'PUT') return handleUpdateSend(request, env, userId, sendId);
      if (method === 'DELETE') return handleDeleteSend(request, env, userId, sendId);
    }

    if (subPath === '/remove-password' && (method === 'PUT' || method === 'POST')) {
      return handleRemoveSendPassword(request, env, userId, sendId);
    }

    if (subPath === '/remove-auth' && (method === 'PUT' || method === 'POST')) {
      return handleRemoveSendAuth(request, env, userId, sendId);
    }

    const sendFileUploadMatch = subPath.match(/^\/file\/([^/]+)\/?$/i);
    if (sendFileUploadMatch) {
      const fileId = sendFileUploadMatch[1];
      if (method === 'GET') return handleGetSendFileUpload(request, env, userId, sendId, fileId);
      if (method === 'POST' || method === 'PUT') return handleUploadSendFile(request, env, userId, sendId, fileId);
    }
  }

  if (path === '/api/policies' || path.startsWith('/api/policies/')) {
    if (method === 'GET') {
      return jsonResponse({ data: [], object: 'list', continuationToken: null });
    }
    return null;
  }

  if (path === '/api/settings/domains' || path === '/settings/domains') {
    if (method === 'GET') return handleGetDomains(env, userId);
    if (method === 'PUT' || method === 'POST') return handleUpdateDomains(request, env, userId);
    return null;
  }

  const authenticatedDeviceResponse = await handleAuthenticatedDeviceRoute(request, env, userId, path, method);
  if (authenticatedDeviceResponse) return authenticatedDeviceResponse;

  const adminResponse = await handleAdminRoute(request, env, currentUser, path, method);
  if (adminResponse) return adminResponse;

  return null;
}
