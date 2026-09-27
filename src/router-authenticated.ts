import { Hono } from 'hono';
import { handleEventRoute } from './handlers/events';
import { errorResponse, jsonResponse, unsupportedResponse } from './utils/response';
import {
  handleGetProfile,
  handleUpdateProfile,
  handleGetKeys,
  handleGetUserPublicKey,
  handleSetKeys,
  handleGetRevisionDate,
  handleSetUserKeyId,
  handleVerifyPassword,
  handleChangePassword,
  handleDeleteAccount,
  handleEmailToken,
  handleChangeEmail,
  handleSetVerifyDevices,
  handleGetTotpStatus,
  handleSetTotpStatus,
  handleGetTotpRecoveryCode,
  handleGetTwoFactorProviders,
  handleGetTwoFactorEmail,
  handleSendTwoFactorEmail,
  handlePutTwoFactorEmail,
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
  handleGetCipherAdmin,
  handleGetOrganizationCiphers,
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
  handleShareCipher,
  handleBulkShareCiphers,
  handleUpdateCipherCollections,
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
import { deviceRoutes } from './router-devices';
import { adminRoutes } from './router-admin';
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
import { organizationRoutes } from './router-org';
import { handleEmergencyAccessRoute } from './handlers/emergency-access';
import { handleAccountLicenseUpload } from './handlers/licenses';
import { handleListAllCollections } from './handlers/organizations';
import type { AppEnv } from './router';

const methodNotAllowed = () => errorResponse('Method not allowed', 405);
const emptyList = () => jsonResponse({ data: [], object: 'list', continuationToken: null });

// Two-factor providers are disabled by provider type: 0 authenticator, 1 email, 3 YubiKey, 7 WebAuthn.
const TWO_FACTOR_AUTHENTICATOR = 0;
const TWO_FACTOR_EMAIL = 1;
const TWO_FACTOR_YUBIKEY = 3;
const TWO_FACTOR_WEBAUTHN = 7;

export const authenticatedRoutes = new Hono<AppEnv>();

authenticatedRoutes.use(async (c, next) => {
  const eventResponse = await handleEventRoute(c.req.raw, c.env, c.get('currentUser'), c.req.path, c.req.method);
  if (eventResponse) return eventResponse;
  await next();
});

authenticatedRoutes.on(['POST', 'PUT', 'DELETE'], [
  '/api/accounts/set-password',
  '/api/accounts/delete-account',
  '/api/accounts/delete-vault',
], () => errorResponse('Not implemented', 501));

authenticatedRoutes.on('DELETE', ['/api/accounts', '/accounts'], (c) => handleDeleteAccount(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.post('/api/accounts/delete', (c) => handleDeleteAccount(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on(['POST', 'PUT'], ['/api/accounts/kdf', '/accounts/kdf'], () => unsupportedResponse('KDF changes are not supported by this server.'));
authenticatedRoutes.on('POST', ['/api/accounts/email-token', '/accounts/email-token'], (c) => handleEmailToken(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('POST', ['/api/accounts/email', '/accounts/email'], (c) => handleChangeEmail(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on(['POST', 'PUT'], [
  '/api/accounts/verify-email',
  '/accounts/verify-email',
  '/api/accounts/verify-email-token',
  '/accounts/verify-email-token',
  '/api/accounts/request-otp',
  '/accounts/request-otp',
  '/api/accounts/verify-otp',
  '/accounts/verify-otp',
], () => unsupportedResponse('Email delivery is not supported by this server.'));

authenticatedRoutes.on('POST', ['/api/two-factor/get-email', '/two-factor/get-email'], (c) => handleGetTwoFactorEmail(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('POST', ['/api/two-factor/send-email', '/two-factor/send-email'], (c) => handleSendTwoFactorEmail(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on(['PUT', 'POST'], ['/api/two-factor/email', '/two-factor/email'], (c) => handlePutTwoFactorEmail(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('DELETE', ['/api/two-factor/email', '/two-factor/email'], (c) => handleDisableTwoFactorProvider(c.req.raw, c.env, c.get('userId'), TWO_FACTOR_EMAIL));
authenticatedRoutes.on('ALL', ['/api/two-factor/email', '/two-factor/email'], methodNotAllowed);

authenticatedRoutes.get('/api/accounts/profile', (c) => handleGetProfile(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.put('/api/accounts/profile', (c) => handleUpdateProfile(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.all('/api/accounts/profile', methodNotAllowed);

authenticatedRoutes.on(['POST', 'PUT'], ['/api/accounts/password', '/api/accounts/change-password'], (c) => handleChangePassword(c.req.raw, c.env, c.get('userId')));

authenticatedRoutes.get('/api/accounts/keys', (c) => handleGetKeys(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.post('/api/accounts/keys', (c) => handleSetKeys(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.all('/api/accounts/keys', methodNotAllowed);

authenticatedRoutes.get('/api/users/:userId{[a-f0-9-]+}/public-key', (c) => handleGetUserPublicKey(c.env, c.req.param('userId')));

authenticatedRoutes.get('/api/accounts/totp', (c) => handleGetTotpStatus(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on(['PUT', 'POST'], '/api/accounts/totp', (c) => handleSetTotpStatus(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('POST', ['/api/accounts/totp/recovery-code', '/api/two-factor/get-recover'], (c) => handleGetTotpRecoveryCode(c.req.raw, c.env, c.get('userId')));

authenticatedRoutes.get('/api/two-factor', (c) => handleGetTwoFactorProviders(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.all('/api/two-factor', methodNotAllowed);
authenticatedRoutes.post('/api/two-factor/get-authenticator', (c) => handleGetTwoFactorAuthenticator(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('POST', ['/api/two-factor/get-yubikey', '/api/two-factor/get-yubi-key'], (c) => handleGetTwoFactorYubiKey(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on(['GET', 'POST'], '/api/two-factor/get-device-verification-settings', (c) => handleGetDeviceVerificationSettings(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on(['PUT', 'POST'], '/api/two-factor/device-verification-settings', (c) => handlePutDeviceVerificationSettings(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.all('/api/two-factor/device-verification-settings', methodNotAllowed);
authenticatedRoutes.post('/api/two-factor/get-webauthn', (c) => handleGetTwoFactorWebAuthn(c.req.raw, c.env, c.get('userId'), c.get('currentUser')));
authenticatedRoutes.post('/api/two-factor/get-webauthn-challenge', (c) => handleGetTwoFactorWebAuthnChallenge(c.req.raw, c.env, c.get('userId'), c.get('currentUser')));

authenticatedRoutes.on(['PUT', 'POST'], '/api/two-factor/authenticator', (c) => handlePutTwoFactorAuthenticator(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.delete('/api/two-factor/authenticator', (c) => handleDisableTwoFactorProvider(c.req.raw, c.env, c.get('userId'), TWO_FACTOR_AUTHENTICATOR));
authenticatedRoutes.all('/api/two-factor/authenticator', methodNotAllowed);

authenticatedRoutes.on(['PUT', 'POST'], ['/api/two-factor/yubikey', '/api/two-factor/yubi-key'], (c) => handlePutTwoFactorYubiKey(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('DELETE', ['/api/two-factor/yubikey', '/api/two-factor/yubi-key'], (c) => handleDisableTwoFactorProvider(c.req.raw, c.env, c.get('userId'), TWO_FACTOR_YUBIKEY));
authenticatedRoutes.on('ALL', ['/api/two-factor/yubikey', '/api/two-factor/yubi-key'], methodNotAllowed);

authenticatedRoutes.delete('/api/two-factor/webauthn/all', (c) => handleDisableTwoFactorProvider(c.req.raw, c.env, c.get('userId'), TWO_FACTOR_WEBAUTHN));
authenticatedRoutes.on(['PUT', 'POST'], '/api/two-factor/webauthn', (c) => handlePutTwoFactorWebAuthn(c.req.raw, c.env, c.get('userId'), c.get('currentUser')));
authenticatedRoutes.delete('/api/two-factor/webauthn', (c) => handleDeleteTwoFactorWebAuthn(c.req.raw, c.env, c.get('userId'), c.get('currentUser')));
authenticatedRoutes.all('/api/two-factor/webauthn', methodNotAllowed);

authenticatedRoutes.on(['PUT', 'POST'], ['/api/two-factor/yubikey/config', '/api/two-factor/yubi-key/config'], (c) => handlePutTwoFactorYubiKeyConfig(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('POST', ['/api/two-factor/yubikey/bootstrap', '/api/two-factor/yubi-key/bootstrap'], (c) => handleBootstrapTwoFactorYubiKeyConfig(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on(['PUT', 'POST'], '/api/two-factor/disable', (c) => handleDisableTwoFactorProvider(c.req.raw, c.env, c.get('userId')));

authenticatedRoutes.get('/api/accounts/revision-date', (c) => handleGetRevisionDate(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.post('/api/accounts/key-management/user-key-id', (c) => handleSetUserKeyId(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.post('/api/accounts/verify-password', (c) => handleVerifyPassword(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on(['PUT', 'POST'], ['/api/accounts/verify-devices', '/accounts/verify-devices'], (c) => handleSetVerifyDevices(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('POST', ['/api/accounts/api-key', '/api/accounts/api_key'], (c) => handleGetApiKey(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('POST', ['/api/accounts/rotate-api-key', '/api/accounts/rotate_api_key'], (c) => handleRotateApiKey(c.req.raw, c.env, c.get('userId')));

authenticatedRoutes.on('GET', ['/api/webauthn', '/webauthn'], (c) => handleGetAccountPasskeyCredentials(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('POST', ['/api/webauthn', '/webauthn'], (c) => handleCreateAccountPasskeyCredential(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('PUT', ['/api/webauthn', '/webauthn'], (c) => handleUpdateAccountPasskeyEncryption(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('ALL', ['/api/webauthn', '/webauthn'], methodNotAllowed);
authenticatedRoutes.on('POST', ['/api/webauthn/attestation-options', '/webauthn/attestation-options'], (c) => handleGetAccountPasskeyAttestationOptions(c.req.raw, c.env, c.get('userId'), c.get('currentUser')));
authenticatedRoutes.on('POST', ['/api/webauthn/assertion-options', '/webauthn/assertion-options'], (c) => handleGetAccountPasskeyUpdateAssertionOptions(c.req.raw, c.env, c.get('userId'), c.get('currentUser')));
authenticatedRoutes.on('POST', ['/api/webauthn/:credentialId/delete', '/webauthn/:credentialId/delete'], (c) => handleDeleteAccountPasskeyCredential(c.req.raw, c.env, c.get('userId'), c.req.param('credentialId'), c.get('currentUser')));

authenticatedRoutes.get('/api/sync', (c) => handleSync(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.get('/api/collections', (c) => handleListAllCollections(c.env, c.get('userId')));

authenticatedRoutes.route('/', organizationRoutes);

authenticatedRoutes.on('POST', ['/api/accounts/license', '/accounts/license'], () => handleAccountLicenseUpload());

authenticatedRoutes.use(async (c, next) => {
  const emergency = await handleEmergencyAccessRoute(c.req.raw, c.env, c.get('currentUser'), c.req.path, c.req.method);
  if (emergency) return emergency;
  await next();
});

authenticatedRoutes.get('/api/ciphers/organization-details', (c) => handleGetOrganizationCiphers(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('GET', ['/api/ciphers', '/api/ciphers/create'], (c) => handleGetCiphers(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('POST', ['/api/ciphers', '/api/ciphers/create'], (c) => handleCreateCipher(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.post('/api/ciphers/import', (c) => handleCiphersImport(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.post('/api/ciphers/delete', (c) => handleBulkDeleteCiphers(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.post('/api/ciphers/delete-permanent', (c) => handleBulkPermanentDeleteCiphers(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.post('/api/ciphers/restore', (c) => handleBulkRestoreCiphers(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on(['PUT', 'POST'], '/api/ciphers/archive', (c) => handleBulkArchiveCiphers(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on(['PUT', 'POST'], '/api/ciphers/unarchive', (c) => handleBulkUnarchiveCiphers(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on(['POST', 'PUT'], '/api/ciphers/move', (c) => handleBulkMoveCiphers(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on(['PUT', 'POST'], '/api/ciphers/share', (c) => handleBulkShareCiphers(c.req.raw, c.env, c.get('userId')));

const cipher = '/api/ciphers/:cipherId{[a-f0-9-]+}';
authenticatedRoutes.get(cipher, (c) => handleGetCipher(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId')));
authenticatedRoutes.on(['PUT', 'POST'], cipher, (c) => handleUpdateCipher(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId')));
authenticatedRoutes.delete(cipher, (c) => handleDeleteCipherCompat(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId')));
authenticatedRoutes.put(`${cipher}/delete`, (c) => handleDeleteCipher(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId')));
authenticatedRoutes.delete(`${cipher}/delete`, (c) => handlePermanentDeleteCipher(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId')));
authenticatedRoutes.put(`${cipher}/restore`, (c) => handleRestoreCipher(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId')));
authenticatedRoutes.on(['PUT', 'POST'], `${cipher}/archive`, (c) => handleArchiveCipher(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId')));
authenticatedRoutes.on(['PUT', 'POST'], `${cipher}/unarchive`, (c) => handleUnarchiveCipher(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId')));
authenticatedRoutes.on(['PUT', 'POST'], `${cipher}/partial`, (c) => handlePartialUpdateCipher(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId')));
authenticatedRoutes.on(['PUT', 'POST'], `${cipher}/share`, (c) => handleShareCipher(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId')));
authenticatedRoutes.on(['PUT', 'POST'], `${cipher}/collections_v2`, (c) => handleUpdateCipherCollections(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId'), 'member'));
authenticatedRoutes.on(['PUT', 'POST'], `${cipher}/collections-admin`, (c) => handleUpdateCipherCollections(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId'), 'admin'));
authenticatedRoutes.get(`${cipher}/admin`, (c) => handleGetCipherAdmin(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId')));
authenticatedRoutes.put(`${cipher}/admin`, (c) => handleUpdateCipher(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId'), true));
authenticatedRoutes.delete(`${cipher}/admin`, (c) => handlePermanentDeleteCipher(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId'), true));
authenticatedRoutes.put(`${cipher}/delete-admin`, (c) => handleDeleteCipher(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId'), true));
authenticatedRoutes.get(`${cipher}/details`, (c) => handleGetCipher(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId')));
authenticatedRoutes.on('POST', [`${cipher}/attachment/v2`, `${cipher}/attachment`], (c) => handleCreateAttachment(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId')));

const attachment = `${cipher}/attachment/:attachmentId{[a-f0-9-]+}`;
authenticatedRoutes.on(['POST', 'PUT'], attachment, (c) => handleUploadAttachment(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId'), c.req.param('attachmentId')));
authenticatedRoutes.get(attachment, (c) => handleGetAttachment(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId'), c.req.param('attachmentId')));
authenticatedRoutes.delete(attachment, (c) => handleDeleteAttachment(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId'), c.req.param('attachmentId')));
authenticatedRoutes.on(['POST', 'PUT'], `${attachment}/metadata`, (c) => handleUpdateAttachmentMetadata(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId'), c.req.param('attachmentId')));
authenticatedRoutes.post(`${attachment}/delete`, (c) => handleDeleteAttachment(c.req.raw, c.env, c.get('userId'), c.req.param('cipherId'), c.req.param('attachmentId')));

authenticatedRoutes.get('/api/folders', (c) => handleGetFolders(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.post('/api/folders', (c) => handleCreateFolder(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.post('/api/folders/delete', (c) => handleBulkDeleteFolders(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.get('/api/folders/:folderId{[a-f0-9-]+}', (c) => handleGetFolder(c.req.raw, c.env, c.get('userId'), c.req.param('folderId')));
authenticatedRoutes.put('/api/folders/:folderId{[a-f0-9-]+}', (c) => handleUpdateFolder(c.req.raw, c.env, c.get('userId'), c.req.param('folderId')));
authenticatedRoutes.delete('/api/folders/:folderId{[a-f0-9-]+}', (c) => handleDeleteFolder(c.req.raw, c.env, c.get('userId'), c.req.param('folderId')));

authenticatedRoutes.on('GET', ['/api/auth-requests', '/auth-requests'], (c) => handleListAuthRequests(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('ALL', ['/api/auth-requests', '/auth-requests'], methodNotAllowed);
authenticatedRoutes.on('GET', ['/api/auth-requests/pending', '/auth-requests/pending'], (c) => handleListPendingAuthRequests(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.on('ALL', ['/api/auth-requests/pending', '/auth-requests/pending'], methodNotAllowed);
authenticatedRoutes.on('POST', ['/api/auth-requests/admin-request', '/auth-requests/admin-request'], (c) => handleCreateAdminAuthRequest(c.req.raw, c.env, c.get('userId'), c.get('currentUser').email));
authenticatedRoutes.on('ALL', ['/api/auth-requests/admin-request', '/auth-requests/admin-request'], methodNotAllowed);
const authRequest = ['/api/auth-requests/:id{[a-f0-9-]+}', '/auth-requests/:id{[a-f0-9-]+}'] as const;
authenticatedRoutes.on('GET', [...authRequest], (c) => handleGetAuthRequest(c.req.raw, c.env, c.get('userId'), c.req.param('id')));
authenticatedRoutes.on('PUT', [...authRequest], (c) => handleUpdateAuthRequest(c.req.raw, c.env, c.get('userId'), c.req.param('id')));
authenticatedRoutes.on('ALL', [...authRequest], methodNotAllowed);

// Collection, organization and policy lists the clients poll but this server answers empty.
authenticatedRoutes.get('/api/collections/*', emptyList);
authenticatedRoutes.on('GET', ['/api/organizations', '/api/organizations/*'], emptyList);

authenticatedRoutes.get('/api/sends', (c) => handleGetSends(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.post('/api/sends', (c) => handleCreateSend(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.post('/api/sends/file/v2', (c) => handleCreateFileSendV2(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.post('/api/sends/delete', (c) => handleBulkDeleteSends(c.req.raw, c.env, c.get('userId')));
authenticatedRoutes.get('/api/sends/:sendId', (c) => handleGetSend(c.req.raw, c.env, c.get('userId'), c.req.param('sendId')));
authenticatedRoutes.put('/api/sends/:sendId', (c) => handleUpdateSend(c.req.raw, c.env, c.get('userId'), c.req.param('sendId')));
authenticatedRoutes.delete('/api/sends/:sendId', (c) => handleDeleteSend(c.req.raw, c.env, c.get('userId'), c.req.param('sendId')));
authenticatedRoutes.on(['PUT', 'POST'], '/api/sends/:sendId/remove-password', (c) => handleRemoveSendPassword(c.req.raw, c.env, c.get('userId'), c.req.param('sendId')));
authenticatedRoutes.on(['PUT', 'POST'], '/api/sends/:sendId/remove-auth', (c) => handleRemoveSendAuth(c.req.raw, c.env, c.get('userId'), c.req.param('sendId')));
authenticatedRoutes.get('/api/sends/:sendId/file/:fileId', (c) => handleGetSendFileUpload(c.req.raw, c.env, c.get('userId'), c.req.param('sendId'), c.req.param('fileId')));
authenticatedRoutes.on(['POST', 'PUT'], '/api/sends/:sendId/file/:fileId', (c) => handleUploadSendFile(c.req.raw, c.env, c.get('userId'), c.req.param('sendId'), c.req.param('fileId')));

authenticatedRoutes.on('GET', ['/api/policies', '/api/policies/*'], emptyList);

authenticatedRoutes.on('GET', ['/api/settings/domains', '/settings/domains'], (c) => handleGetDomains(c.env, c.get('userId')));
authenticatedRoutes.on(['PUT', 'POST'], ['/api/settings/domains', '/settings/domains'], (c) => handleUpdateDomains(c.req.raw, c.env, c.get('userId')));

authenticatedRoutes.route('/', deviceRoutes);

authenticatedRoutes.route('/', adminRoutes);
