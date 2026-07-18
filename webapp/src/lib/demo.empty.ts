import type { AppMainRoutesProps } from '@/components/AppMainRoutes';
import type { CompletedLogin, InitialAppBootstrapState } from '@/lib/app-auth';
import type { AdminBackupSettings } from '@/lib/api/backup';
import type { AdminInvite, AdminUser, AuthorizedDevice, Cipher, Folder, Send } from '@/lib/types';

export const IS_DEMO_MODE = false;

export const DEMO_CIPHERS: Cipher[] = [];
export const DEMO_ADMIN_INVITES: AdminInvite[] = [];
export const DEMO_ADMIN_USERS: AdminUser[] = [];
export const DEMO_AUTHORIZED_DEVICES: AuthorizedDevice[] = [];
export const DEMO_FOLDERS: Folder[] = [];
export const DEMO_SENDS: Send[] = [];

export function createDemoBackupSettings(): AdminBackupSettings {
  return { destinations: [] };
}

export function createDemoInitialBootstrapState(): InitialAppBootstrapState {
  return {
    defaultKdfIterations: 600000,
    registrationInviteRequired: true,
    websiteIconsEnabled: true,
    jwtWarning: null,
    session: null,
    phase: 'login',
  };
}

export function createDemoCompletedLogin(): CompletedLogin {
  throw new Error('Demo mode is not available in this build.');
}

export function createDemoMainRoutesProps(base: AppMainRoutesProps): AppMainRoutesProps {
  return base;
}

export function getDemoPublicSend(): null {
  return null;
}

export function demoBrandIconUrl(_host: string): string {
  return '';
}
