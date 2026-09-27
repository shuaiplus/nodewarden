import { pruneEvents } from './services/events';
import { purgeExpiredEmailOtps } from './services/email-otp';
import { purgeSecretsTrash } from './services/storage-secret-repo';
import { syncVaultAdminRoles } from './services/vault-admin-role';
import { Env } from './types';
import { NotificationsHub } from './durable/notifications-hub';
import { BackupTransferRunner } from './durable/backup-transfer-runner';
import type { PlatformEvent } from './services/queue-publisher';
import * as orgRepo from './services/storage-org-repo';
import { app } from './router';
import { applyCors, applySecurityHeaders, jsonResponse } from './utils/response';
import { runScheduledBackupIfDue } from './handlers/backup';
import { approveExpiredEmergencyAccess, remindPendingEmergencyAccess } from './handlers/emergency-access';
import { isBackendRequestPath } from './web-vault-visibility';
import { initializeDatabase } from './db/migrate';
import { withoutQueryParams } from './db/client';

let dbInitialized = false;
let dbInitError: string | null = null;
let dbInitPromise: Promise<void> | null = null;

async function ensureDatabaseInitialized(env: Env): Promise<void> {
  if (dbInitialized) return;

  if (!dbInitPromise) {
    dbInitPromise = (async () => {
      await initializeDatabase(env.DB);
      try {
        await syncVaultAdminRoles(env);
      } catch {
        console.error('Vault administrator role sync failed during initialization');
      }
      dbInitialized = true;
      dbInitError = null;
    })()
      .catch((error: unknown) => {
        console.error('Failed to initialize database:', withoutQueryParams(error));
        dbInitError = error instanceof Error ? error.message : 'Unknown database initialization error';
      })
      .finally(() => {
        dbInitPromise = null;
      });
  }

  await dbInitPromise;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Trailing slashes are trimmed so routes match either form.
    const url = new URL(request.url);
    const normalizedPathname = url.pathname.length <= 1 ? url.pathname : url.pathname.replace(/\/+$/, '');
    let normalizedRequest = request;
    if (normalizedPathname !== url.pathname) {
      url.pathname = normalizedPathname;
      normalizedRequest = new Request(url.toString(), request);
    }

    if (
      env.ASSETS &&
      (normalizedRequest.method === 'GET' || normalizedRequest.method === 'HEAD') &&
      !isBackendRequestPath(url.pathname)
    ) {
      const assetResponse = await env.ASSETS.fetch(normalizedRequest);
      const contentType = String(assetResponse.headers.get('Content-Type') || '').toLowerCase();
      const shouldNoIndex = url.pathname === '/robots.txt' || contentType.includes('text/html');
      if (!shouldNoIndex) return applyCors(normalizedRequest, assetResponse, env);
      const headers = new Headers(assetResponse.headers);
      headers.set('X-Robots-Tag', 'noindex, nofollow, noarchive, nosnippet');
      return applyCors(
        normalizedRequest,
        new Response(assetResponse.body, {
          status: assetResponse.status,
          statusText: assetResponse.statusText,
          headers,
        }),
        env,
      );
    }

    await ensureDatabaseInitialized(env);
    if (dbInitError) {
      // Log full error server-side, return generic message to client.
      console.error('DB init error (not forwarded to client):', dbInitError);
      const resp = jsonResponse(
        {
          error: 'Database not initialized',
          error_description: 'Database initialization failed. Check server logs for details.',
          ErrorModel: {
            Message: 'Service temporarily unavailable',
            Object: 'error',
          },
        },
        500,
      );
      return applyCors(normalizedRequest, resp, env);
    }

    return applySecurityHeaders(normalizedRequest, await app.fetch(normalizedRequest, env, ctx));
  },

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    void controller;
    await ensureDatabaseInitialized(env);
    if (dbInitError) {
      console.error('Skipping scheduled backup because DB init failed:', dbInitError);
      return;
    }
    ctx.waitUntil(
      Promise.all([
        pruneEvents(env).catch(() => console.error('Event cleanup failed')),
        purgeExpiredEmailOtps(env).catch(() => console.error('Email code cleanup failed')),
        runScheduledBackupIfDue(env).catch((error) => {
          console.error('Scheduled backup failed:', withoutQueryParams(error));
        }),
        purgeSecretsTrash(env.DB).catch((error) => {
          console.error('Secrets Manager trash purge failed:', withoutQueryParams(error));
        }),
        approveExpiredEmergencyAccess(env).catch((error) => {
          console.error('Emergency access timeout job failed:', withoutQueryParams(error));
        }),
        remindPendingEmergencyAccess(env).catch((error) => {
          console.error('Emergency access reminder job failed:', withoutQueryParams(error));
        }),
      ]),
    );
  },

  async queue(batch: MessageBatch<PlatformEvent>, env: Env): Promise<void> {
    await ensureDatabaseInitialized(env);
    for (const message of batch.messages) {
      try {
        const event = message.body;
        if (event.type === 'org.revision') {
          await orgRepo.bumpOrgMemberRevisions(env.DB, event.orgId);
        }
        message.ack();
      } catch (error) {
        console.error('Queue event failed:', withoutQueryParams(error));
        message.retry({ delaySeconds: 30 });
      }
    }
  },
};

export { NotificationsHub };
export { BackupTransferRunner };
