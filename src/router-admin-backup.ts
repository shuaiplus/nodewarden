import type { Env, User } from './types';
import {
  handleAdminExportBackup,
  handleDownloadAdminRemoteBackup,
  handleDeleteAdminRemoteBackup,
  handleDownloadAdminBackupAttachment,
  handleGetAdminBackupSettings,
  handleGetAdminBackupSettingsRepairState,
  handleInspectAdminRemoteBackup,
  handleAdminImportBackup,
  handleListAdminRemoteBackups,
  handleRepairAdminBackupSettings,
  handleRestoreAdminRemoteBackup,
  handleRunAdminConfiguredBackup,
  handleUpdateAdminBackupSettings,
} from './handlers/backup';
import { errorResponse } from './utils/response';

export async function handleAdminBackupRoute(
  request: Request,
  env: Env,
  actorUser: User,
  path: string,
  method: string
): Promise<Response | null> {
  if (path === '/api/admin/backup/export' && method === 'POST') {
    return handleAdminExportBackup(request, env, actorUser);
  }

  if (path === '/api/admin/backup/blob') {
    // POST only: this endpoint requires master-password verification, and a GET
    // could only carry that credential in the query string, where it would leak
    // into request logs, proxy logs, browser history and Referer headers.
    // The credential is the same value clients send to /identity/connect/token,
    // so a leaked copy is enough to sign in as this admin.
    if (method === 'POST') {
      return handleDownloadAdminBackupAttachment(request, env, actorUser);
    }
    if (method === 'GET') {
      return errorResponse(
        'Use POST with a JSON body for this endpoint. Credentials must not be sent in the URL.',
        405
      );
    }
    return null;
  }

  if (path === '/api/admin/backup/settings') {
    if (method === 'GET') return handleGetAdminBackupSettings(request, env, actorUser);
    if (method === 'PUT') return handleUpdateAdminBackupSettings(request, env, actorUser);
    return null;
  }

  if (path === '/api/admin/backup/settings/repair') {
    if (method === 'GET') return handleGetAdminBackupSettingsRepairState(request, env, actorUser);
    if (method === 'POST') return handleRepairAdminBackupSettings(request, env, actorUser);
    return null;
  }

  if (path === '/api/admin/backup/run' && method === 'POST') {
    return handleRunAdminConfiguredBackup(request, env, actorUser);
  }

  if (path === '/api/admin/backup/remote' && method === 'GET') {
    return handleListAdminRemoteBackups(request, env, actorUser);
  }

  if (path === '/api/admin/backup/remote/download' && method === 'POST') {
    return handleDownloadAdminRemoteBackup(request, env, actorUser);
  }

  if (path === '/api/admin/backup/remote/integrity' && method === 'POST') {
    return handleInspectAdminRemoteBackup(request, env, actorUser);
  }

  if (path === '/api/admin/backup/remote/file' && method === 'DELETE') {
    return handleDeleteAdminRemoteBackup(request, env, actorUser);
  }

  if (path === '/api/admin/backup/remote/restore' && method === 'POST') {
    return handleRestoreAdminRemoteBackup(request, env, actorUser);
  }

  if (path === '/api/admin/backup/import' && method === 'POST') {
    return handleAdminImportBackup(request, env, actorUser);
  }

  return null;
}
