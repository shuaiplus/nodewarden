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

  if (path === '/api/admin/backup/blob' && (method === 'GET' || method === 'POST')) {
    return handleDownloadAdminBackupAttachment(request, env, actorUser);
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
