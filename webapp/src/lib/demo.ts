import type { AppMainRoutesProps } from '@/components/AppMainRoutes';
import type { CompletedLogin, InitialAppBootstrapState } from '@/lib/app-auth';
import type {
  AdminBackupImportResponse,
  AdminBackupRunResponse,
  AdminBackupSettings,
  RemoteBackupBrowserResponse,
} from '@/lib/api/backup';
import type {
  AdminInvite,
  AdminUser,
  AuditLogEntry,
  AuthorizedDevice,
  Cipher,
  Folder,
  Profile,
  Send,
  SendDraft,
  SessionState,
  VaultDraft,
} from '@/lib/types';
import { t } from '@/lib/i18n';
import { dispatchBackupProgress } from '@/lib/backup-restore-progress';

type Notify = (type: 'success' | 'error' | 'warning', text: string) => void;
type StateSetter<T> = (next: T[] | ((prev: T[]) => T[])) => void;
type BackupSettingsSetter = (next: AdminBackupSettings | ((prev: AdminBackupSettings) => AdminBackupSettings)) => void;

interface DemoRouteState {
  ciphers: Cipher[];
  folders: Folder[];
  sends: Send[];
  users: AdminUser[];
  invites: AdminInvite[];
  authorizedDevices: AuthorizedDevice[];
  backupSettings: AdminBackupSettings;
  setCiphers: StateSetter<Cipher>;
  setFolders: StateSetter<Folder>;
  setSends: StateSetter<Send>;
  setUsers: StateSetter<AdminUser>;
  setInvites: StateSetter<AdminInvite>;
  setAuthorizedDevices: StateSetter<AuthorizedDevice>;
  setBackupSettings: BackupSettingsSetter;
}

export const IS_DEMO_MODE = __NODEWARDEN_DEMO__;

const DEMO_USER_ID = 'demo-user-001';
const DEMO_NOW = '2026-05-04T08:00:00.000Z';

export const DEMO_PROFILE: Profile = {
  id: DEMO_USER_ID,
  email: 'demo@nodewarden.app',
  name: 'NodeWarden Demo',
  key: 'demo-profile-key',
  masterPasswordHint: 'In demo mode, any input unlocks the vault.',
  privateKey: null,
  publicKey: 'demo-public-key',
  role: 'admin',
  premium: true,
  object: 'profile',
};

export const DEMO_SESSION: SessionState = {
  accessToken: 'demo-access-token',
  refreshToken: 'demo-refresh-token',
  email: DEMO_PROFILE.email,
  authMode: 'token',
  symEncKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
  symMacKey: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
};

export const DEMO_FOLDERS: Folder[] = [
  { id: 'folder-work', name: 'Work', decName: 'Work', creationDate: DEMO_NOW, revisionDate: DEMO_NOW },
  { id: 'folder-personal', name: 'Personal', decName: 'Personal', creationDate: DEMO_NOW, revisionDate: DEMO_NOW },
  { id: 'folder-devops', name: 'DevOps', decName: 'DevOps', creationDate: DEMO_NOW, revisionDate: DEMO_NOW },
];

export const DEMO_CIPHERS: Cipher[] = [
  {
    id: 'cipher-login-github',
    type: 1,
    folderId: 'folder-work',
    favorite: true,
    reprompt: 0,
    name: 'GitHub',
    notes: 'Main engineering organization account.',
    decName: 'GitHub',
    decNotes: 'Main engineering organization account.',
    creationDate: '2026-04-12T09:20:00.000Z',
    revisionDate: '2026-05-01T10:15:00.000Z',
    login: {
      username: 'demo@nodewarden.app',
      password: 'correct-horse-battery-staple',
      totp: 'otpauth://totp/GitHub:demo%40nodewarden.app?secret=JBSWY3DPEHPK3PXP&issuer=GitHub',
      decUsername: 'demo@nodewarden.app',
      decPassword: 'correct-horse-battery-staple',
      decTotp: 'otpauth://totp/GitHub:demo%40nodewarden.app?secret=JBSWY3DPEHPK3PXP&issuer=GitHub',
      uris: [{ uri: 'https://github.com', decUri: 'https://github.com', match: null }],
      fido2Credentials: [{ creationDate: '2026-04-14T08:10:00.000Z', rpId: 'github.com' }],
    },
    fields: [
      { type: 0, name: 'Recovery email', value: 'ops@nodewarden.app', decName: 'Recovery email', decValue: 'ops@nodewarden.app' },
      { type: 1, name: 'Backup code', value: 'NW-DEMO-2026', decName: 'Backup code', decValue: 'NW-DEMO-2026' },
    ],
    passwordHistory: [
      { password: 'old-demo-password', decPassword: 'old-demo-password', lastUsedDate: '2026-04-01T12:00:00.000Z' },
    ],
    attachments: [
      { id: 'att-github-recovery', fileName: 'recovery-codes.txt', decFileName: 'recovery-codes.txt', size: 1540, sizeName: '1.5 KB' },
    ],
  },
  {
    id: 'cipher-login-cloudflare',
    type: 1,
    folderId: 'folder-devops',
    favorite: true,
    reprompt: 1,
    name: 'Cloudflare Dashboard',
    notes: 'Reprompt preview item.',
    decName: 'Cloudflare Dashboard',
    decNotes: 'Reprompt preview item.',
    creationDate: '2026-04-18T10:45:00.000Z',
    revisionDate: '2026-05-02T14:00:00.000Z',
    login: {
      username: 'admin@nodewarden.app',
      password: 'demo-cloudflare-password',
      totp: 'otpauth://totp/Cloudflare:admin%40nodewarden.app?secret=JBSWY3DPEHPK3PXP&issuer=Cloudflare',
      decUsername: 'admin@nodewarden.app',
      decPassword: 'demo-cloudflare-password',
      decTotp: 'otpauth://totp/Cloudflare:admin%40nodewarden.app?secret=JBSWY3DPEHPK3PXP&issuer=Cloudflare',
      uris: [{ uri: 'https://dash.cloudflare.com', decUri: 'https://dash.cloudflare.com', match: null }],
    },
  },
  {
    id: 'cipher-login-google',
    type: 1,
    folderId: 'folder-work',
    favorite: true,
    reprompt: 0,
    name: 'Google Workspace',
    notes: 'Shared admin mailbox with passkey and recovery fields.',
    decName: 'Google Workspace',
    decNotes: 'Shared admin mailbox with passkey and recovery fields.',
    creationDate: '2026-04-19T09:30:00.000Z',
    revisionDate: '2026-05-03T09:30:00.000Z',
    login: {
      username: 'workspace.admin@nodewarden.app',
      password: 'demo-google-password-2026',
      totp: 'otpauth://totp/Google:workspace.admin%40nodewarden.app?secret=JBSWY3DPEHPK3PXP&issuer=Google',
      decUsername: 'workspace.admin@nodewarden.app',
      decPassword: 'demo-google-password-2026',
      decTotp: 'otpauth://totp/Google:workspace.admin%40nodewarden.app?secret=JBSWY3DPEHPK3PXP&issuer=Google',
      uris: [{ uri: 'https://accounts.google.com', decUri: 'https://accounts.google.com', match: null }],
      fido2Credentials: [{ creationDate: '2026-04-20T07:00:00.000Z', rpId: 'google.com' }],
      passwordRevisionDate: '2026-05-03T09:30:00.000Z',
    },
    fields: [
      { type: 0, name: 'Recovery email', value: 'recovery@nodewarden.app', decName: 'Recovery email', decValue: 'recovery@nodewarden.app' },
      { type: 1, name: 'Backup code', value: 'GOOG-NW-2026-01', decName: 'Backup code', decValue: 'GOOG-NW-2026-01' },
      { type: 2, name: 'Admin console', value: 'true', decName: 'Admin console', decValue: 'true' },
    ],
    passwordHistory: [
      { password: 'demo-google-old-password', decPassword: 'demo-google-old-password', lastUsedDate: '2026-03-30T09:00:00.000Z' },
    ],
  },
  {
    id: 'cipher-login-microsoft',
    type: 1,
    folderId: 'folder-work',
    favorite: false,
    reprompt: 0,
    name: 'Microsoft 365',
    notes: 'Demo tenant administrator.',
    decName: 'Microsoft 365',
    decNotes: 'Demo tenant administrator.',
    creationDate: '2026-04-20T09:30:00.000Z',
    revisionDate: '2026-05-03T10:30:00.000Z',
    login: {
      username: 'admin@nodewarden.onmicrosoft.com',
      password: 'demo-microsoft-password-2026',
      totp: 'otpauth://totp/Microsoft:admin%40nodewarden.onmicrosoft.com?secret=JBSWY3DPEHPK3PXP&issuer=Microsoft',
      decUsername: 'admin@nodewarden.onmicrosoft.com',
      decPassword: 'demo-microsoft-password-2026',
      decTotp: 'otpauth://totp/Microsoft:admin%40nodewarden.onmicrosoft.com?secret=JBSWY3DPEHPK3PXP&issuer=Microsoft',
      uris: [{ uri: 'https://login.microsoftonline.com', decUri: 'https://login.microsoftonline.com', match: null }],
      fido2Credentials: [{ creationDate: '2026-04-21T07:00:00.000Z', rpId: 'login.microsoftonline.com' }],
      passwordRevisionDate: '2026-05-03T10:30:00.000Z',
    },
    fields: [
      { type: 0, name: 'Tenant ID', value: '11111111-2222-3333-4444-555555555555', decName: 'Tenant ID', decValue: '11111111-2222-3333-4444-555555555555' },
      { type: 1, name: 'Recovery code', value: 'MSFT-NW-2026-02', decName: 'Recovery code', decValue: 'MSFT-NW-2026-02' },
      { type: 2, name: 'Conditional access', value: 'true', decName: 'Conditional access', decValue: 'true' },
    ],
  },
  {
    id: 'cipher-login-amazon',
    type: 1,
    folderId: 'folder-personal',
    favorite: false,
    reprompt: 0,
    name: 'Amazon',
    notes: 'Shopping account with TOTP for code-list preview.',
    decName: 'Amazon',
    decNotes: 'Shopping account with TOTP for code-list preview.',
    creationDate: '2026-04-21T09:30:00.000Z',
    revisionDate: '2026-05-03T11:30:00.000Z',
    login: {
      username: 'demo@nodewarden.app',
      password: 'demo-amazon-password-2026',
      totp: 'otpauth://totp/Amazon:demo%40nodewarden.app?secret=JBSWY3DPEHPK3PXP&issuer=Amazon',
      decUsername: 'demo@nodewarden.app',
      decPassword: 'demo-amazon-password-2026',
      decTotp: 'otpauth://totp/Amazon:demo%40nodewarden.app?secret=JBSWY3DPEHPK3PXP&issuer=Amazon',
      uris: [{ uri: 'https://www.amazon.com', decUri: 'https://www.amazon.com', match: null }],
      passwordRevisionDate: '2026-05-03T11:30:00.000Z',
    },
    fields: [
      { type: 0, name: 'Phone', value: '+1 555 0101', decName: 'Phone', decValue: '+1 555 0101' },
      { type: 1, name: 'Recovery code', value: 'AMZN-NW-2026-03', decName: 'Recovery code', decValue: 'AMZN-NW-2026-03' },
    ],
  },
  {
    id: 'cipher-login-netflix',
    type: 1,
    folderId: 'folder-personal',
    favorite: false,
    reprompt: 0,
    name: 'Netflix',
    notes: 'Consumer account example.',
    decName: 'Netflix',
    decNotes: 'Consumer account example.',
    creationDate: '2026-04-22T09:30:00.000Z',
    revisionDate: '2026-05-03T12:30:00.000Z',
    login: {
      username: 'family@nodewarden.app',
      password: 'demo-netflix-password-2026',
      totp: 'otpauth://totp/Netflix:family%40nodewarden.app?secret=JBSWY3DPEHPK3PXP&issuer=Netflix',
      decUsername: 'family@nodewarden.app',
      decPassword: 'demo-netflix-password-2026',
      decTotp: 'otpauth://totp/Netflix:family%40nodewarden.app?secret=JBSWY3DPEHPK3PXP&issuer=Netflix',
      uris: [{ uri: 'https://www.netflix.com', decUri: 'https://www.netflix.com', match: null }],
      passwordRevisionDate: '2026-05-03T12:30:00.000Z',
    },
    fields: [
      { type: 0, name: 'Profile PIN', value: '0426', decName: 'Profile PIN', decValue: '0426' },
      { type: 1, name: 'Backup code', value: 'NFLX-NW-2026-04', decName: 'Backup code', decValue: 'NFLX-NW-2026-04' },
    ],
  },
  {
    id: 'cipher-login-paypal',
    type: 1,
    folderId: 'folder-personal',
    favorite: true,
    reprompt: 1,
    name: 'PayPal',
    notes: 'Financial account with reprompt and TOTP.',
    decName: 'PayPal',
    decNotes: 'Financial account with reprompt and TOTP.',
    creationDate: '2026-04-23T09:30:00.000Z',
    revisionDate: '2026-05-03T13:30:00.000Z',
    login: {
      username: 'billing@nodewarden.app',
      password: 'demo-paypal-password-2026',
      totp: 'otpauth://totp/PayPal:billing%40nodewarden.app?secret=JBSWY3DPEHPK3PXP&issuer=PayPal',
      decUsername: 'billing@nodewarden.app',
      decPassword: 'demo-paypal-password-2026',
      decTotp: 'otpauth://totp/PayPal:billing%40nodewarden.app?secret=JBSWY3DPEHPK3PXP&issuer=PayPal',
      uris: [{ uri: 'https://www.paypal.com', decUri: 'https://www.paypal.com', match: null }],
      fido2Credentials: [{ creationDate: '2026-04-24T07:00:00.000Z', rpId: 'paypal.com' }],
      passwordRevisionDate: '2026-05-03T13:30:00.000Z',
    },
    fields: [
      { type: 0, name: 'Recovery phone', value: '+1 555 0102', decName: 'Recovery phone', decValue: '+1 555 0102' },
      { type: 1, name: 'Backup code', value: 'PYPL-NW-2026-05', decName: 'Backup code', decValue: 'PYPL-NW-2026-05' },
      { type: 2, name: 'Business account', value: 'true', decName: 'Business account', decValue: 'true' },
    ],
  },
  {
    id: 'cipher-card-company',
    type: 3,
    folderId: 'folder-work',
    favorite: false,
    name: 'Company Visa',
    decName: 'Company Visa',
    notes: 'Demo card data.',
    decNotes: 'Demo card data.',
    creationDate: '2026-03-22T09:00:00.000Z',
    revisionDate: DEMO_NOW,
    card: {
      cardholderName: 'NodeWarden Demo',
      number: '4111 1111 1111 1111',
      brand: 'Visa',
      expMonth: '12',
      expYear: '2030',
      code: '123',
      decCardholderName: 'NodeWarden Demo',
      decNumber: '4111 1111 1111 1111',
      decBrand: 'Visa',
      decExpMonth: '12',
      decExpYear: '2030',
      decCode: '123',
    },
  },
  {
    id: 'cipher-identity-team',
    type: 4,
    folderId: 'folder-personal',
    name: 'Travel Identity',
    decName: 'Travel Identity',
    notes: 'Sample identity for form preview.',
    decNotes: 'Sample identity for form preview.',
    creationDate: '2026-02-20T11:00:00.000Z',
    revisionDate: DEMO_NOW,
    identity: {
      title: 'Mr.',
      firstName: 'Alex',
      middleName: 'Morgan',
      lastName: 'Chen',
      username: 'alex.demo',
      company: 'NodeWarden Labs',
      ssn: '123-45-6789',
      passportNumber: 'X12345678',
      licenseNumber: 'D1234567',
      email: 'alex.demo@example.com',
      phone: '+1 555 0100',
      address1: '100 Demo Street',
      address2: 'Suite 42',
      address3: 'Reception: Demo Desk',
      city: 'San Francisco',
      state: 'CA',
      postalCode: '94105',
      country: 'United States',
      decTitle: 'Mr.',
      decFirstName: 'Alex',
      decMiddleName: 'Morgan',
      decLastName: 'Chen',
      decUsername: 'alex.demo',
      decCompany: 'NodeWarden Labs',
      decSsn: '123-45-6789',
      decPassportNumber: 'X12345678',
      decLicenseNumber: 'D1234567',
      decEmail: 'alex.demo@example.com',
      decPhone: '+1 555 0100',
      decAddress1: '100 Demo Street',
      decAddress2: 'Suite 42',
      decAddress3: 'Reception: Demo Desk',
      decCity: 'San Francisco',
      decState: 'CA',
      decPostalCode: '94105',
      decCountry: 'United States',
    },
  },
  {
    id: 'cipher-note-release',
    type: 2,
    folderId: null,
    favorite: false,
    name: 'Release checklist',
    decName: 'Release checklist',
    notes: 'Review build, dry-run deploy, and release notes before shipping.',
    decNotes: 'Review build, dry-run deploy, and release notes before shipping.',
    creationDate: '2026-04-25T08:30:00.000Z',
    revisionDate: DEMO_NOW,
    secureNote: { type: 0 },
  },
  {
    id: 'cipher-ssh-prod',
    type: 5,
    folderId: 'folder-devops',
    favorite: false,
    name: 'Production SSH key',
    decName: 'Production SSH key',
    notes: 'Fake SSH key material for UI preview.',
    decNotes: 'Fake SSH key material for UI preview.',
    creationDate: '2026-01-10T08:30:00.000Z',
    revisionDate: DEMO_NOW,
    sshKey: {
      privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nDEMO-PRIVATE-KEY\n-----END OPENSSH PRIVATE KEY-----',
      publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDemoNodeWardenKey demo@nodewarden',
      keyFingerprint: 'SHA256:demoNodeWardenFingerprint',
      decPrivateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nDEMO-PRIVATE-KEY\n-----END OPENSSH PRIVATE KEY-----',
      decPublicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDemoNodeWardenKey demo@nodewarden',
      decFingerprint: 'SHA256:demoNodeWardenFingerprint',
    },
  },
  // --- Duplicate detection demo pairs (exact, login-site, login-credentials, password) ---
  {
    id: 'cipher-dup-exact-a',
    type: 1,
    folderId: 'folder-work',
    favorite: false,
    name: 'Internal VPN',
    decName: 'Internal VPN',
    creationDate: '2026-04-10T08:00:00.000Z',
    revisionDate: '2026-04-28T10:00:00.000Z',
    login: {
      username: 'vpn-user',
      password: 'vpn-secret-2026', // gitguardian:ignore
      decUsername: 'vpn-user',
      decPassword: 'vpn-secret-2026', // gitguardian:ignore
      uris: [{ uri: 'https://vpn.internal.example.com', decUri: 'https://vpn.internal.example.com', match: null }],
    },
  },
  {
    id: 'cipher-dup-exact-b',
    type: 1,
    folderId: 'folder-work',
    favorite: false,
    name: 'Internal VPN',
    decName: 'Internal VPN',
    creationDate: '2026-03-15T08:00:00.000Z',
    revisionDate: '2026-04-30T10:00:00.000Z',
    login: {
      username: 'vpn-user',
      password: 'vpn-secret-2026', // gitguardian:ignore
      decUsername: 'vpn-user',
      decPassword: 'vpn-secret-2026', // gitguardian:ignore
      uris: [{ uri: 'https://vpn.internal.example.com', decUri: 'https://vpn.internal.example.com', match: null }],
    },
  },
  {
    id: 'cipher-dup-site-a',
    type: 1,
    folderId: 'folder-devops',
    favorite: false,
    name: 'AWS Console',
    decName: 'AWS Console',
    creationDate: '2026-03-01T08:00:00.000Z',
    revisionDate: '2026-04-25T09:00:00.000Z',
    login: {
      username: 'aws-admin',
      password: 'aws-secure-password', // gitguardian:ignore
      decUsername: 'aws-admin',
      decPassword: 'aws-secure-password', // gitguardian:ignore
      uris: [{ uri: 'https://console.aws.amazon.com', decUri: 'https://console.aws.amazon.com', match: null }],
    },
  },
  {
    id: 'cipher-dup-site-b',
    type: 1,
    folderId: 'folder-devops',
    favorite: false,
    name: 'Amazon Web Services',
    decName: 'Amazon Web Services',
    creationDate: '2026-02-20T08:00:00.000Z',
    revisionDate: '2026-04-20T09:00:00.000Z',
    login: {
      username: 'aws-admin',
      password: 'aws-secure-password', // gitguardian:ignore
      decUsername: 'aws-admin',
      decPassword: 'aws-secure-password', // gitguardian:ignore
      uris: [{ uri: 'https://console.aws.amazon.com', decUri: 'https://console.aws.amazon.com', match: null }],
    },
  },
  {
    id: 'cipher-dup-cred-a',
    type: 1,
    folderId: 'folder-personal',
    favorite: false,
    name: 'Personal Blog',
    decName: 'Personal Blog',
    creationDate: '2026-01-10T08:00:00.000Z',
    revisionDate: '2026-04-15T10:00:00.000Z',
    login: {
      username: 'my-account@example.com',
      password: 'shared-credential', // gitguardian:ignore
      decUsername: 'my-account@example.com',
      decPassword: 'shared-credential', // gitguardian:ignore
      uris: [{ uri: 'https://blog.example.com', decUri: 'https://blog.example.com', match: null }],
    },
  },
  {
    id: 'cipher-dup-cred-b',
    type: 1,
    folderId: 'folder-personal',
    favorite: false,
    name: 'Forum Account',
    decName: 'Forum Account',
    creationDate: '2026-01-15T08:00:00.000Z',
    revisionDate: '2026-04-18T10:00:00.000Z',
    login: {
      username: 'my-account@example.com',
      password: 'shared-credential', // gitguardian:ignore
      decUsername: 'my-account@example.com',
      decPassword: 'shared-credential', // gitguardian:ignore
      uris: [{ uri: 'https://forum.example.com', decUri: 'https://forum.example.com', match: null }],
    },
  },
  {
    id: 'cipher-dup-pw-a',
    type: 1,
    folderId: 'folder-personal',
    favorite: false,
    name: 'Old Forum',
    decName: 'Old Forum',
    creationDate: '2025-06-01T08:00:00.000Z',
    revisionDate: '2026-03-01T10:00:00.000Z',
    login: {
      username: 'legacy-user',
      password: 'reused-password-2020', // gitguardian:ignore
      decUsername: 'legacy-user',
      decPassword: 'reused-password-2020', // gitguardian:ignore
      uris: [{ uri: 'https://old-forum.example.com', decUri: 'https://old-forum.example.com', match: null }],
    },
  },
  {
    id: 'cipher-dup-pw-b',
    type: 1,
    folderId: 'folder-personal',
    favorite: false,
    name: 'Legacy CMS',
    decName: 'Legacy CMS',
    creationDate: '2025-05-10T08:00:00.000Z',
    revisionDate: '2026-02-15T10:00:00.000Z',
    login: {
      username: 'cms-admin',
      password: 'reused-password-2020', // gitguardian:ignore
      decUsername: 'cms-admin',
      decPassword: 'reused-password-2020', // gitguardian:ignore
      uris: [{ uri: 'https://cms.example.com', decUri: 'https://cms.example.com', match: null }],
    },
  },
  {
    id: 'cipher-archived',
    type: 1,
    folderId: 'folder-personal',
    favorite: false,
    name: 'Archived demo login',
    decName: 'Archived demo login',
    notes: 'Archived state preview.',
    decNotes: 'Archived state preview.',
    archivedDate: '2026-05-03T06:00:00.000Z',
    creationDate: '2026-04-05T06:00:00.000Z',
    revisionDate: '2026-05-03T06:00:00.000Z',
    login: {
      username: 'archived@example.com',
      password: 'archived-demo',
      decUsername: 'archived@example.com',
      decPassword: 'archived-demo',
      uris: [{ uri: 'https://example.com', decUri: 'https://example.com', match: null }],
    },
  },
];

export const DEMO_SENDS: Send[] = [
  {
    id: 'send-demo-note',
    accessId: 'demo-note',
    type: 0,
    name: 'Onboarding note',
    decName: 'Onboarding note',
    notes: 'Text Send preview.',
    decNotes: 'Text Send preview.',
    text: { text: 'Welcome to NodeWarden demo mode.', hidden: false },
    decText: 'Welcome to NodeWarden demo mode.',
    accessCount: 3,
    maxAccessCount: 10,
    disabled: false,
    deletionDate: '2026-05-18T08:00:00.000Z',
    expirationDate: null,
    revisionDate: DEMO_NOW,
    shareUrl: '/#/send/demo-note/demo-key',
  },
  {
    id: 'send-demo-file',
    accessId: 'demo-file',
    type: 1,
    name: 'Design handoff.zip',
    decName: 'Design handoff.zip',
    notes: 'File Send preview.',
    decNotes: 'File Send preview.',
    accessCount: 1,
    maxAccessCount: null,
    disabled: false,
    deletionDate: '2026-05-11T08:00:00.000Z',
    expirationDate: '2026-05-08T08:00:00.000Z',
    revisionDate: DEMO_NOW,
    shareUrl: '/#/send/demo-file/demo-key',
    file: {
      id: 'send-file-001',
      fileName: 'design-handoff.zip',
      size: 248000,
      sizeName: '242 KB',
    },
  },
];

export function getDemoPublicSend(accessId: string): {
  id: string;
  type: 0 | 1;
  decName: string;
  decText?: string;
  decFileName?: string;
  expirationDate: string | null;
  file?: { id: string; fileName: string; sizeName: string } | null;
} | null {
  const normalized = String(accessId || '').trim().toLowerCase();
  if (normalized === 'demo-note') {
    return {
      id: 'send-demo-note',
      type: 0,
      decName: 'Onboarding note',
      decText: 'Welcome to NodeWarden demo mode. This public Send page is served entirely from demo data.',
      expirationDate: '2026-05-18T08:00:00.000Z',
      file: null,
    };
  }
  if (normalized === 'demo-file') {
    return {
      id: 'send-demo-file',
      type: 1,
      decName: 'Design handoff.zip',
      decFileName: 'design-handoff.zip',
      expirationDate: '2026-05-08T08:00:00.000Z',
      file: {
        id: 'send-file-001',
        fileName: 'design-handoff.zip',
        sizeName: '242 KB',
      },
    };
  }
  return null;
}

export const DEMO_ADMIN_USERS: AdminUser[] = [
  { id: DEMO_USER_ID, email: DEMO_PROFILE.email, name: DEMO_PROFILE.name, role: 'admin', status: 'active' },
  { id: 'demo-user-002', email: 'viewer@example.com', name: 'Read Only Viewer', role: 'user', status: 'active' },
  { id: 'demo-user-003', email: 'suspended@example.com', name: 'Suspended User', role: 'user', status: 'banned' },
];

export const DEMO_ADMIN_INVITES: AdminInvite[] = [
  {
    code: 'DEMO-INVITE-2026',
    inviteLink: '/register?invite=DEMO-INVITE-2026',
    status: 'active',
    expiresAt: '2026-05-11T08:00:00.000Z',
  },
  {
    code: 'USED-DEMO',
    inviteLink: '/register?invite=USED-DEMO',
    status: 'used',
    expiresAt: '2026-05-01T08:00:00.000Z',
  },
];

export const DEMO_AUTHORIZED_DEVICES: AuthorizedDevice[] = [
  {
    id: 'demo-device-browser',
    name: 'Chrome on Windows',
    systemName: 'Windows',
    deviceNote: 'Demo browser session',
    identifier: 'demo-device-browser',
    type: 9,
    creationDate: '2026-05-01T08:00:00.000Z',
    revisionDate: DEMO_NOW,
    lastSeenAt: DEMO_NOW,
    hasStoredDevice: true,
    online: true,
    trusted: true,
    trustedTokenCount: 1,
    trustedUntil: '2026-06-03T08:00:00.000Z',
  },
  {
    id: 'demo-device-mobile',
    name: 'iPhone',
    systemName: 'iOS',
    deviceNote: 'Mobile app preview',
    identifier: 'demo-device-mobile',
    type: 1,
    creationDate: '2026-04-29T08:00:00.000Z',
    revisionDate: DEMO_NOW,
    lastSeenAt: '2026-05-03T20:30:00.000Z',
    hasStoredDevice: true,
    online: false,
    trusted: false,
    trustedTokenCount: 0,
    trustedUntil: null,
  },
];

export const DEMO_BACKUP_SETTINGS: AdminBackupSettings = {
  destinations: [
    {
      id: 'demo-webdav',
      name: 'Demo WebDAV',
      type: 'webdav',
      includeAttachments: true,
      destination: {
        baseUrl: 'https://dav.example.com/nodewarden',
        username: 'demo-backup',
        password: 'demo-password',
        remotePath: 'nodewarden',
      },
      schedule: {
        enabled: true,
        intervalHours: 24,
        startTime: '03:00',
        timezone: 'UTC',
        retentionCount: 14,
      },
      runtime: {
        lastAttemptAt: '2026-05-04T03:00:00.000Z',
        lastAttemptLocalDate: '2026-05-04',
        lastSuccessAt: '2026-05-04T03:01:12.000Z',
        lastErrorAt: null,
        lastErrorMessage: null,
        lastUploadedFileName: 'nodewarden_backup_20260504_030112_a1b2c.zip',
        lastUploadedSizeBytes: 1048576,
        lastUploadedDestination: 'Demo WebDAV',
      },
    },
  ],
};

export const DEMO_AUDIT_LOGS: AuditLogEntry[] = [
  {
    id: 'demo-log-auth-login',
    actorUserId: DEMO_USER_ID,
    actorEmail: DEMO_PROFILE.email,
    action: 'auth.login.success',
    category: 'auth',
    level: 'info',
    targetType: null,
    targetId: null,
    targetUserEmail: null,
    metadata: JSON.stringify({ ip: '203.0.113.42', device: 'Chrome 125 on Windows', location: 'San Francisco, US' }),
    createdAt: '2026-07-08T14:32:10.000Z',
    object: 'auditLog',
  },
  {
    id: 'demo-log-auth-failed',
    actorUserId: null,
    actorEmail: 'unknown@example.com',
    action: 'auth.login.failed',
    category: 'auth',
    level: 'warn',
    targetType: null,
    targetId: null,
    targetUserEmail: null,
    metadata: JSON.stringify({ ip: '198.51.100.7', reason: 'invalid_password', attemptCount: 3 }),
    createdAt: '2026-07-08T13:15:00.000Z',
    object: 'auditLog',
  },
  {
    id: 'demo-log-auth-2fa',
    actorUserId: DEMO_USER_ID,
    actorEmail: DEMO_PROFILE.email,
    action: 'auth.totp.enabled',
    category: 'auth',
    level: 'security',
    targetType: null,
    targetId: null,
    targetUserEmail: null,
    metadata: JSON.stringify({ ip: '203.0.113.42', trigger: 'user_initiated' }),
    createdAt: '2026-07-07T09:00:00.000Z',
    object: 'auditLog',
  },
  {
    id: 'demo-log-auth-refresh-failed',
    actorUserId: DEMO_USER_ID,
    actorEmail: DEMO_PROFILE.email,
    action: 'auth.refresh.failed.token_expired',
    category: 'auth',
    level: 'error',
    targetType: null,
    targetId: 'demo-device-browser',
    targetUserEmail: null,
    metadata: JSON.stringify({ ip: '203.0.113.42', device: 'Chrome 125 on Windows' }),
    createdAt: '2026-07-06T18:45:30.000Z',
    object: 'auditLog',
  },
  {
    id: 'demo-log-security-password',
    actorUserId: DEMO_USER_ID,
    actorEmail: DEMO_PROFILE.email,
    action: 'user.password.changed',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: DEMO_USER_ID,
    targetUserEmail: DEMO_PROFILE.email,
    metadata: JSON.stringify({ ip: '203.0.113.42', trigger: 'user_initiated' }),
    createdAt: '2026-07-05T10:00:00.000Z',
    object: 'auditLog',
  },
  {
    id: 'demo-log-security-user-banned',
    actorUserId: DEMO_USER_ID,
    actorEmail: DEMO_PROFILE.email,
    action: 'admin.user.banned',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: 'demo-user-003',
    targetUserEmail: 'suspended@example.com',
    metadata: JSON.stringify({ ip: '203.0.113.42', reason: 'violation_of_tos' }),
    createdAt: '2026-07-04T16:20:00.000Z',
    object: 'auditLog',
  },
  {
    id: 'demo-log-security-user-register',
    actorUserId: null,
    actorEmail: 'newuser@example.com',
    action: 'user.register.completed',
    category: 'security',
    level: 'info',
    targetType: 'user',
    targetId: 'demo-user-004',
    targetUserEmail: 'newuser@example.com',
    metadata: JSON.stringify({ ip: '192.0.2.55', invite: 'DEMO-INVITE-2026' }),
    createdAt: '2026-07-03T08:30:00.000Z',
    object: 'auditLog',
  },
  {
    id: 'demo-log-device-trusted',
    actorUserId: DEMO_USER_ID,
    actorEmail: DEMO_PROFILE.email,
    action: 'device.trusted.added',
    category: 'device',
    level: 'info',
    targetType: 'device',
    targetId: 'demo-device-mobile',
    targetUserEmail: null,
    metadata: JSON.stringify({ deviceName: 'iPhone', os: 'iOS 18', ip: '203.0.113.42' }),
    createdAt: '2026-07-02T12:15:00.000Z',
    object: 'auditLog',
  },
  {
    id: 'demo-log-device-removed',
    actorUserId: DEMO_USER_ID,
    actorEmail: DEMO_PROFILE.email,
    action: 'device.removed',
    category: 'device',
    level: 'warn',
    targetType: 'device',
    targetId: 'demo-device-old',
    targetUserEmail: null,
    metadata: JSON.stringify({ deviceName: 'Firefox on Linux', ip: '198.51.100.20', trigger: 'user_initiated' }),
    createdAt: '2026-07-01T09:45:00.000Z',
    object: 'auditLog',
  },
  {
    id: 'demo-log-device-all-revoked',
    actorUserId: DEMO_USER_ID,
    actorEmail: DEMO_PROFILE.email,
    action: 'device.all_trust_revoked',
    category: 'device',
    level: 'security',
    targetType: null,
    targetId: null,
    targetUserEmail: null,
    metadata: JSON.stringify({ ip: '203.0.113.42', trigger: 'password_change' }),
    createdAt: '2026-07-01T09:00:00.000Z',
    object: 'auditLog',
  },
  {
    id: 'demo-log-data-backup',
    actorUserId: DEMO_USER_ID,
    actorEmail: DEMO_PROFILE.email,
    action: 'admin.backup.run.completed',
    category: 'data',
    level: 'info',
    targetType: null,
    targetId: null,
    targetUserEmail: null,
    metadata: JSON.stringify({ fileName: 'nodewarden_backup_20260701_030000.zip', size: '1.2 MB', destination: 'Demo WebDAV' }),
    createdAt: '2026-07-01T03:00:00.000Z',
    object: 'auditLog',
  },
  {
    id: 'demo-log-data-restore',
    actorUserId: DEMO_USER_ID,
    actorEmail: DEMO_PROFILE.email,
    action: 'admin.backup.restore.completed',
    category: 'data',
    level: 'warn',
    targetType: null,
    targetId: null,
    targetUserEmail: null,
    metadata: JSON.stringify({ fileName: 'nodewarden_backup_20260628_030000.zip', checksum: 'verified' }),
    createdAt: '2026-06-30T14:00:00.000Z',
    object: 'auditLog',
  },
  {
    id: 'demo-log-data-export',
    actorUserId: DEMO_USER_ID,
    actorEmail: DEMO_PROFILE.email,
    action: 'admin.export.completed',
    category: 'data',
    level: 'info',
    targetType: null,
    targetId: null,
    targetUserEmail: null,
    metadata: JSON.stringify({ format: 'encrypted_json', totalItems: 24 }),
    createdAt: '2026-06-28T11:30:00.000Z',
    object: 'auditLog',
  },
  {
    id: 'demo-log-system-settings',
    actorUserId: DEMO_USER_ID,
    actorEmail: DEMO_PROFILE.email,
    action: 'admin.settings.updated',
    category: 'system',
    level: 'info',
    targetType: null,
    targetId: null,
    targetUserEmail: null,
    metadata: JSON.stringify({ changedKeys: ['signupsAllowed', 'kdfIterations'], ip: '203.0.113.42' }),
    createdAt: '2026-06-25T08:00:00.000Z',
    object: 'auditLog',
  },
  {
    id: 'demo-log-system-invite',
    actorUserId: DEMO_USER_ID,
    actorEmail: DEMO_PROFILE.email,
    action: 'admin.invite.created',
    category: 'system',
    level: 'info',
    targetType: 'invite',
    targetId: 'DEMO-INVITE-2026',
    targetUserEmail: null,
    metadata: JSON.stringify({ expiresIn: '168h', ip: '203.0.113.42' }),
    createdAt: '2026-06-20T10:00:00.000Z',
    object: 'auditLog',
  },
  {
    id: 'demo-log-system-config',
    actorUserId: DEMO_USER_ID,
    actorEmail: DEMO_PROFILE.email,
    action: 'admin.config.updated',
    category: 'system',
    level: 'warn',
    targetType: null,
    targetId: null,
    targetUserEmail: null,
    metadata: JSON.stringify({ changedKeys: ['smtp.host', 'smtp.port'], ip: '203.0.113.42' }),
    createdAt: '2026-06-18T15:30:00.000Z',
    object: 'auditLog',
  },
];

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export function createDemoBackupSettings(): AdminBackupSettings {
  return cloneJson(DEMO_BACKUP_SETTINGS);
}

function createDemoId(prefix: string): string {
  const random = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  return `demo-${prefix}-${random}`;
}

function cipherFromDraft(draft: VaultDraft, current?: Cipher | null): Cipher {
  const now = new Date().toISOString();
  const type = Number(draft.type || current?.type || 1) || 1;
  const next: Cipher = {
    ...(current || {}),
    id: current?.id || createDemoId('cipher'),
    type,
    folderId: draft.folderId || null,
    favorite: !!draft.favorite,
    reprompt: draft.reprompt ? 1 : 0,
    name: draft.name || '',
    notes: draft.notes || '',
    decName: draft.name || '',
    decNotes: draft.notes || '',
    creationDate: current?.creationDate || now,
    revisionDate: now,
    deletedDate: current?.deletedDate || null,
    archivedDate: current?.archivedDate || null,
  };

  next.login = type === 1 ? {
    ...(current?.login || {}),
    username: draft.loginUsername || '',
    password: draft.loginPassword || '',
    totp: draft.loginTotp || '',
    decUsername: draft.loginUsername || '',
    decPassword: draft.loginPassword || '',
    decTotp: draft.loginTotp || '',
    uris: draft.loginUris.map((uri) => ({
      ...(uri.extra || {}),
      uri: uri.uri || '',
      decUri: uri.uri || '',
      match: uri.match ?? null,
    })),
    fido2Credentials: draft.loginFido2Credentials.map((credential) => ({ ...credential })),
  } : null;

  next.card = type === 3 ? {
    ...(current?.card || {}),
    cardholderName: draft.cardholderName || '',
    number: draft.cardNumber || '',
    brand: draft.cardBrand || '',
    expMonth: draft.cardExpMonth || '',
    expYear: draft.cardExpYear || '',
    code: draft.cardCode || '',
    decCardholderName: draft.cardholderName || '',
    decNumber: draft.cardNumber || '',
    decBrand: draft.cardBrand || '',
    decExpMonth: draft.cardExpMonth || '',
    decExpYear: draft.cardExpYear || '',
    decCode: draft.cardCode || '',
  } : null;

  next.identity = type === 4 ? {
    ...(current?.identity || {}),
    title: draft.identTitle || '',
    firstName: draft.identFirstName || '',
    middleName: draft.identMiddleName || '',
    lastName: draft.identLastName || '',
    username: draft.identUsername || '',
    company: draft.identCompany || '',
    ssn: draft.identSsn || '',
    passportNumber: draft.identPassportNumber || '',
    licenseNumber: draft.identLicenseNumber || '',
    email: draft.identEmail || '',
    phone: draft.identPhone || '',
    address1: draft.identAddress1 || '',
    address2: draft.identAddress2 || '',
    address3: draft.identAddress3 || '',
    city: draft.identCity || '',
    state: draft.identState || '',
    postalCode: draft.identPostalCode || '',
    country: draft.identCountry || '',
    decTitle: draft.identTitle || '',
    decFirstName: draft.identFirstName || '',
    decMiddleName: draft.identMiddleName || '',
    decLastName: draft.identLastName || '',
    decUsername: draft.identUsername || '',
    decCompany: draft.identCompany || '',
    decSsn: draft.identSsn || '',
    decPassportNumber: draft.identPassportNumber || '',
    decLicenseNumber: draft.identLicenseNumber || '',
    decEmail: draft.identEmail || '',
    decPhone: draft.identPhone || '',
    decAddress1: draft.identAddress1 || '',
    decAddress2: draft.identAddress2 || '',
    decAddress3: draft.identAddress3 || '',
    decCity: draft.identCity || '',
    decState: draft.identState || '',
    decPostalCode: draft.identPostalCode || '',
    decCountry: draft.identCountry || '',
  } : null;

  next.sshKey = type === 5 ? {
    ...(current?.sshKey || {}),
    privateKey: draft.sshPrivateKey || '',
    publicKey: draft.sshPublicKey || '',
    keyFingerprint: draft.sshFingerprint || '',
    fingerprint: draft.sshFingerprint || '',
    decPrivateKey: draft.sshPrivateKey || '',
    decPublicKey: draft.sshPublicKey || '',
    decFingerprint: draft.sshFingerprint || '',
  } : null;

  next.fields = draft.customFields.map((field) => ({
    type: field.type,
    name: field.label,
    value: field.value,
    decName: field.label,
    decValue: field.value,
  }));

  return next;
}

function sendFromDraft(draft: SendDraft, current?: Send | null): Send {
  const now = new Date().toISOString();
  const isFile = draft.type === 'file';
  const fileName = String(draft.file?.name || current?.file?.fileName || 'demo-file.txt').trim();
  const fileSize = typeof draft.file?.size === 'number' ? draft.file.size : Number(current?.file?.size || 0);
  const deletionDays = Math.max(1, Number(draft.deletionDays || 7) || 7);
  const expirationDays = Number(draft.expirationDays || 0) || 0;
  return {
    ...(current || {}),
    id: current?.id || createDemoId('send'),
    accessId: current?.accessId || createDemoId('access'),
    type: isFile ? 1 : 0,
    name: draft.name || '',
    decName: draft.name || '',
    notes: draft.notes || '',
    decNotes: draft.notes || '',
    text: isFile ? null : { text: draft.text || '', hidden: false },
    decText: isFile ? '' : draft.text || '',
    key: current?.key || createDemoId('send-key'),
    accessCount: current?.accessCount || 0,
    maxAccessCount: draft.maxAccessCount ? Number(draft.maxAccessCount) : null,
    disabled: !!draft.disabled,
    deletionDate: new Date(Date.now() + deletionDays * 86400_000).toISOString(),
    expirationDate: expirationDays > 0 ? new Date(Date.now() + expirationDays * 86400_000).toISOString() : null,
    revisionDate: now,
    shareUrl: current?.shareUrl || (isFile ? '/#/send/demo-file/demo-key' : '/#/send/demo-note/demo-key'),
    file: isFile ? {
      id: current?.file?.id || createDemoId('send-file'),
      fileName,
      size: fileSize,
      sizeName: fileSize > 0 ? `${Math.ceil(fileSize / 1024)} KB` : '0 KB',
    } : null,
  };
}

function resetDemoVaultState(state: DemoRouteState): void {
  state.setFolders(DEMO_FOLDERS.map((folder) => ({ ...folder })));
  state.setCiphers(DEMO_CIPHERS.map((cipher) => cloneJson(cipher)));
  state.setSends(DEMO_SENDS.map((send) => cloneJson(send)));
  state.setBackupSettings(createDemoBackupSettings());
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

async function runDemoRemoteRestoreProgress(fileName: string): Promise<void> {
  const stages = [
    ['txt_backup_restore_progress_remote_fetch_title', 'txt_backup_restore_progress_remote_fetch_detail'],
    ['txt_backup_restore_progress_remote_shadow_title', 'txt_backup_restore_progress_remote_shadow_detail'],
    ['txt_backup_restore_progress_remote_data_title', 'txt_backup_restore_progress_remote_data_detail'],
    ['txt_backup_restore_progress_remote_files_title', 'txt_backup_restore_progress_remote_files_detail'],
    ['txt_backup_restore_progress_remote_finalize_title', 'txt_backup_restore_progress_remote_finalize_detail'],
  ] as const;

  for (let index = 0; index < stages.length; index += 1) {
    const [stageTitle, stageDetail] = stages[index];
    dispatchBackupProgress({
      operation: 'backup-restore',
      source: 'remote',
      step: String(index + 1),
      fileName,
      stageTitle,
      stageDetail,
      done: false,
    });
    await sleep(2000);
  }

  dispatchBackupProgress({
    operation: 'backup-restore',
    source: 'remote',
    step: 'complete',
    fileName,
    stageTitle: 'txt_backup_restore_progress_remote_finalize_title',
    stageDetail: 'txt_backup_restore_progress_remote_finalize_detail',
    done: true,
    ok: true,
  });
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

export function createDemoCompletedLogin(emailInput: string = ''): CompletedLogin {
  const email = String(emailInput || '').trim().toLowerCase() || DEMO_PROFILE.email;
  const profile = { ...DEMO_PROFILE, email };
  const session = { ...DEMO_SESSION, email };
  return {
    session,
    profile,
    profilePromise: Promise.resolve(profile),
  };
}

function createDemoImportResult() {
  return {
    totalItems: 0,
    folderCount: 0,
    typeCounts: [],
    attachmentCount: 0,
    importedAttachmentCount: 0,
    failedAttachments: [],
  };
}

function createDemoImportBackupResult(): AdminBackupImportResponse {
  return {
    object: 'instance-backup-import',
    imported: {
      config: 0,
      users: 0,
      userRevisions: 0,
      folders: 0,
      ciphers: 0,
      attachments: 0,
      attachmentFiles: 0,
    },
    skipped: {
      reason: 'demo-read-only',
      attachments: 0,
      items: [],
    },
  };
}

function createDemoRemoteBrowser(destinationId: string, path: string = ''): RemoteBackupBrowserResponse {
  return {
    object: 'backup-remote-browser',
    destinationId,
    destinationName: 'Demo WebDAV',
    provider: 'webdav',
    currentPath: path,
    parentPath: path ? '' : null,
    items: [
      {
        path: 'nodewarden_backup_20260504_030112_a1b2c.zip',
        name: 'nodewarden_backup_20260504_030112_a1b2c.zip',
        isDirectory: false,
        size: 1048576,
        modifiedAt: '2026-05-04T03:01:12.000Z',
      },
      {
        path: 'archive',
        name: 'archive',
        isDirectory: true,
        size: null,
        modifiedAt: '2026-05-01T03:01:12.000Z',
      },
    ],
  };
}

function createDemoBackupRun(settings: AdminBackupSettings, destinationId: string | null | undefined): AdminBackupRunResponse {
  const destination = settings.destinations.find((item) => item.id === destinationId) || settings.destinations[0] || DEMO_BACKUP_SETTINGS.destinations[0];
  return {
    object: 'backup-run',
    result: {
      fileName: 'nodewarden_backup_20260504_030112_a1b2c.zip',
      fileSize: 1048576,
      provider: destination.type,
      remotePath: 'nodewarden/nodewarden_backup_20260504_030112_a1b2c.zip',
    },
    settings,
  };
}

export function createDemoMainRoutesProps(base: AppMainRoutesProps, notify: Notify, state: DemoRouteState): AppMainRoutesProps {
  const readonly = async () => {
    notify('warning', t('txt_demo_readonly_message'));
  };
  const readonlyVoid = () => {
    notify('warning', t('txt_demo_readonly_message'));
  };
  const readonlyString = async () => {
    notify('warning', t('txt_demo_readonly_message'));
    return 'DEMO-READ-ONLY';
  };

  return {
    ...base,
    profile: DEMO_PROFILE,
    profileLoading: false,
    decryptedCiphers: state.ciphers,
    decryptedFolders: state.folders,
    decryptedSends: state.sends,
    vaultError: '',
    ciphersLoading: false,
    foldersLoading: false,
    sendsLoading: false,
    users: state.users,
    invites: state.invites,
    adminLoading: false,
    adminError: '',
    totpEnabled: true,
    passkey2faEnabled: false,
    authorizedDevices: state.authorizedDevices,
    authorizedDevicesLoading: false,
    authorizedDevicesError: '',
    domainRulesLoading: false,
    domainRulesError: '',
    onImport: async () => {
      await readonly();
      return createDemoImportResult();
    },
    onImportEncryptedRaw: async () => {
      await readonly();
      return createDemoImportResult();
    },
    onExport: readonly,
    onCreateVaultItem: async (draft) => {
      const created = cipherFromDraft(draft);
      state.setCiphers((prev) => [created, ...prev]);
      notify('success', t('txt_item_created'));
    },
    onUpdateVaultItem: async (cipher, draft) => {
      const updated = cipherFromDraft(draft, cipher);
      state.setCiphers((prev) => prev.map((item) => (item.id === cipher.id ? updated : item)));
      notify('success', t('txt_item_updated'));
    },
    onDeleteVaultItem: async (cipher) => {
      if (cipher.deletedDate || (cipher as { deletedAt?: string | null }).deletedAt) {
        state.setCiphers((prev) => prev.filter((item) => item.id !== cipher.id));
        notify('success', t('txt_item_deleted_permanently'));
        return;
      }
      const deletedDate = new Date().toISOString();
      state.setCiphers((prev) => prev.map((item) => (
        item.id === cipher.id ? { ...item, deletedDate, archivedDate: null, revisionDate: deletedDate } : item
      )));
      notify('success', t('txt_item_deleted'));
    },
    onArchiveVaultItem: async (cipher) => {
      const archivedDate = new Date().toISOString();
      state.setCiphers((prev) => prev.map((item) => (
        item.id === cipher.id ? { ...item, archivedDate, deletedDate: null, revisionDate: archivedDate } : item
      )));
      notify('success', t('txt_item_archived'));
    },
    onUnarchiveVaultItem: async (cipher) => {
      const revisionDate = new Date().toISOString();
      state.setCiphers((prev) => prev.map((item) => (
        item.id === cipher.id ? { ...item, archivedDate: null, revisionDate } : item
      )));
      notify('success', t('txt_item_unarchived'));
    },
    onBulkDeleteVaultItems: async (ids) => {
      const idSet = new Set(ids);
      const deletedDate = new Date().toISOString();
      state.setCiphers((prev) => prev.map((item) => (
        idSet.has(item.id) ? { ...item, deletedDate, archivedDate: null, revisionDate: deletedDate } : item
      )));
      notify('success', t('txt_deleted_selected_items'));
    },
    onBulkPermanentDeleteVaultItems: async (ids) => {
      const idSet = new Set(ids);
      state.setCiphers((prev) => prev.filter((item) => !idSet.has(item.id)));
      notify('success', t('txt_deleted_selected_items_permanently'));
    },
    onRestoreVaultItems: async (ids) => {
      const idSet = new Set(ids);
      state.setCiphers((prev) => prev.map((item) => (idSet.has(item.id) ? { ...item, deletedDate: null } : item)));
      notify('success', t('txt_restored_selected_items'));
    },
    onBulkRestoreVaultItems: async (ids) => {
      const idSet = new Set(ids);
      state.setCiphers((prev) => prev.map((item) => (idSet.has(item.id) ? { ...item, deletedDate: null } : item)));
      notify('success', t('txt_restored_selected_items'));
    },
    onBulkArchiveVaultItems: async (ids) => {
      const idSet = new Set(ids);
      const archivedDate = new Date().toISOString();
      state.setCiphers((prev) => prev.map((item) => (
        idSet.has(item.id) ? { ...item, archivedDate, deletedDate: null, revisionDate: archivedDate } : item
      )));
      notify('success', t('txt_archived_selected_items'));
    },
    onBulkUnarchiveVaultItems: async (ids) => {
      const idSet = new Set(ids);
      state.setCiphers((prev) => prev.map((item) => (idSet.has(item.id) ? { ...item, archivedDate: null } : item)));
      notify('success', t('txt_unarchived_selected_items'));
    },
    onBulkMoveVaultItems: async (ids, folderId) => {
      const idSet = new Set(ids);
      state.setCiphers((prev) => prev.map((item) => (idSet.has(item.id) ? { ...item, folderId } : item)));
      notify('success', t('txt_moved_selected_items'));
    },
    onVerifyMasterPassword: async () => {},
    onCreateFolder: async (name) => {
      const trimmed = name.trim();
      if (!trimmed) {
        notify('error', t('txt_folder_name_is_required'));
        return;
      }
      state.setFolders((prev) => [{ id: createDemoId('folder'), name: trimmed, decName: trimmed, creationDate: new Date().toISOString(), revisionDate: new Date().toISOString() }, ...prev]);
      notify('success', t('txt_folder_created'));
    },
    onRenameFolder: async (folderId, name) => {
      const trimmed = name.trim();
      state.setFolders((prev) => prev.map((folder) => (folder.id === folderId ? { ...folder, name: trimmed, decName: trimmed, revisionDate: new Date().toISOString() } : folder)));
      notify('success', t('txt_folder_updated'));
    },
    onDeleteFolder: async (folderId) => {
      state.setFolders((prev) => prev.filter((folder) => folder.id !== folderId));
      state.setCiphers((prev) => prev.map((cipher) => (cipher.folderId === folderId ? { ...cipher, folderId: null } : cipher)));
      notify('success', t('txt_folder_deleted'));
    },
    onBulkDeleteFolders: async (folderIds) => {
      const idSet = new Set(folderIds);
      state.setFolders((prev) => prev.filter((folder) => !idSet.has(folder.id)));
      state.setCiphers((prev) => prev.map((cipher) => (cipher.folderId && idSet.has(cipher.folderId) ? { ...cipher, folderId: null } : cipher)));
      notify('success', t('txt_folders_deleted'));
    },
    onDownloadVaultAttachment: async () => {
      notify('success', t('txt_demo_download_prepared'));
    },
    onRefreshVault: async () => {
      resetDemoVaultState(state);
      notify('success', t('txt_demo_data_reset'));
    },
    onCreateSend: async (draft, autoCopyLink) => {
      const created = sendFromDraft(draft);
      state.setSends((prev) => [created, ...prev]);
      if (autoCopyLink && created.shareUrl && typeof navigator !== 'undefined') {
        void navigator.clipboard?.writeText(new URL(created.shareUrl, window.location.origin).toString()).catch(() => undefined);
      }
      notify('success', t('txt_send_created'));
    },
    onUpdateSend: async (send, draft, autoCopyLink) => {
      const updated = sendFromDraft(draft, send);
      state.setSends((prev) => prev.map((item) => (item.id === send.id ? updated : item)));
      if (autoCopyLink && updated.shareUrl && typeof navigator !== 'undefined') {
        void navigator.clipboard?.writeText(new URL(updated.shareUrl, window.location.origin).toString()).catch(() => undefined);
      }
      notify('success', t('txt_send_updated'));
    },
    onDeleteSend: async (send) => {
      state.setSends((prev) => prev.filter((item) => item.id !== send.id));
      notify('success', t('txt_send_deleted'));
    },
    onBulkDeleteSends: async (ids) => {
      const idSet = new Set(ids);
      state.setSends((prev) => prev.filter((item) => !idSet.has(item.id)));
      notify('success', t('txt_deleted_selected_sends'));
    },
    onChangePassword: readonly,
    onSavePasswordHint: readonly,
    onEnableTotp: readonly,
    onOpenDisableTotp: readonlyVoid,
    onGetTwoFactorPasskeySettings: async () => ({ enabled: false, keys: [] }),
    onCreateTwoFactorPasskey: async () => {
      await readonly();
      return { enabled: false, keys: [] };
    },
    onDeleteTwoFactorPasskey: async () => {
      await readonly();
      return { enabled: false, keys: [] };
    },
    onDisableTwoFactorPasskeys: readonly,
    onGetRecoveryCode: readonlyString,
    onGetApiKey: readonlyString,
    onRotateApiKey: readonlyString,
    onListAccountPasskeys: async () => [],
    onCreateAccountPasskey: async () => {
      await readonly();
      return null;
    },
    onEnableAccountPasskeyDirectUnlock: readonly,
    onDeleteAccountPasskey: readonly,
    onLoadAuditLogs: async (filters) => {
      const limit = Number(filters.limit || 50) || 50;
      const offset = Number(filters.offset || 0) || 0;
      let filtered = DEMO_AUDIT_LOGS.filter((log) => {
        if (filters.category && filters.category !== 'all' && log.category !== filters.category) return false;
        if (filters.level && filters.level !== 'all' && log.level !== filters.level) return false;
        if (filters.q) {
          const q = filters.q.toLowerCase();
          if (!log.action.toLowerCase().includes(q) && !(log.actorEmail || '').toLowerCase().includes(q)) return false;
        }
        if (filters.from && new Date(log.createdAt).getTime() < new Date(filters.from).getTime()) return false;
        if (filters.to && new Date(log.createdAt).getTime() > new Date(filters.to).getTime()) return false;
        return true;
      });
      filtered.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
      const total = filtered.length;
      const sliced = filtered.slice(offset, offset + limit);
      return {
        logs: sliced,
        total,
        limit,
        offset: offset + sliced.length,
        hasMore: offset + sliced.length < total,
      };
    },
    onLockTimeoutChange: readonlyVoid,
    onSessionTimeoutActionChange: readonlyVoid,
    onRefreshAuthorizedDevices: async () => {
      notify('success', t('txt_demo_devices_refreshed'));
    },
    onRefreshDomainRules: () => {
      notify('success', t('txt_domain_rules_refreshed'));
    },
    onSaveDomainRules: readonly,
    onRenameAuthorizedDevice: async (device, name) => {
      const normalized = String(name || '').trim();
      if (!normalized) {
        notify('error', t('txt_device_note_required'));
        return;
      }
      state.setAuthorizedDevices((prev) => prev.map((item) => (
        item.identifier === device.identifier
          ? { ...item, name: normalized, deviceNote: normalized, revisionDate: new Date().toISOString() }
          : item
      )));
      notify('success', t('txt_device_note_updated'));
    },
    onRevokeDeviceTrust: (device) => {
      state.setAuthorizedDevices((prev) => prev.map((item) => (
        item.identifier === device.identifier
          ? { ...item, trusted: false, trustedUntil: null, trustedTokenCount: 0, revisionDate: new Date().toISOString() }
          : item
      )));
      notify('success', t('txt_device_authorization_revoked'));
    },
    onTrustDevicePermanently: (device) => {
      state.setAuthorizedDevices((prev) => prev.map((item) => (
        item.identifier === device.identifier && item.trusted
          ? { ...item, trustedUntil: '2099-12-31T23:59:59.000Z', revisionDate: new Date().toISOString() }
          : item
      )));
      notify('success', t('txt_device_trusted_permanently'));
    },
    onRemoveDevice: (device) => {
      state.setAuthorizedDevices((prev) => prev.filter((item) => item.identifier !== device.identifier));
      notify('success', t('txt_device_removed'));
    },
    onRevokeAllDeviceTrust: () => {
      state.setAuthorizedDevices((prev) => prev.map((item) => ({ ...item, trusted: false, trustedUntil: null, trustedTokenCount: 0 })));
      notify('success', t('txt_all_device_authorizations_revoked'));
    },
    onRemoveAllDevices: () => {
      state.setAuthorizedDevices([]);
      notify('success', t('txt_all_devices_removed'));
    },
    onCreateInvite: async (hours) => {
      const code = `DEMO-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
      const expiresAt = new Date(Date.now() + Math.max(1, Number(hours || 168)) * 3600_000).toISOString();
      state.setInvites((prev) => [{
        code,
        inviteLink: `/register?invite=${code}`,
        status: 'active',
        expiresAt,
      }, ...prev]);
      notify('success', t('txt_invite_created'));
    },
    onRefreshAdmin: () => {
      notify('success', t('txt_demo_admin_refreshed'));
    },
    onDeleteInvalidInvites: async () => {
      const now = Date.now();
      state.setInvites((prev) => prev.filter((invite) => (
        invite.status === 'active' && (!invite.expiresAt || new Date(invite.expiresAt).getTime() > now)
      )));
      notify('success', t('txt_invalid_invites_deleted'));
    },
    onDeleteAllInvites: async () => {
      state.setInvites([]);
      notify('success', t('txt_all_invites_deleted'));
    },
    onToggleUserStatus: async (userId, status) => {
      state.setUsers((prev) => prev.map((user) => (
        user.id === userId ? { ...user, status: status === 'active' ? 'banned' : 'active' } : user
      )));
      notify('success', t('txt_user_status_updated'));
    },
    onDeleteUser: async (userId) => {
      state.setUsers((prev) => prev.filter((user) => user.id !== userId));
      notify('success', t('txt_user_deleted'));
    },
    onDeleteInvite: async (code) => {
      state.setInvites((prev) => prev.filter((invite) => invite.code !== code));
      notify('success', t('txt_invite_deleted'));
    },
    onLoadAuditLogSettings: async () => ({ retentionDays: 90, maxEntries: null }),
    onSaveAuditLogSettings: async (settings) => {
      notify('success', t('txt_log_settings_saved'));
      return settings;
    },
    onClearAuditLogs: async () => {
      notify('success', t('txt_logs_cleared'));
      return 0;
    },
    onExportBackup: async (_masterPassword: string) => {
      notify('success', t('txt_backup_export_success'));
    },
    onImportBackup: async (_masterPassword: string, _file: File, _replaceExisting?: boolean) => {
      resetDemoVaultState(state);
      notify('success', t('txt_backup_import_success_relogin'));
      return createDemoImportBackupResult();
    },
    onImportBackupAllowingChecksumMismatch: async (_masterPassword: string, _file: File, _replaceExisting?: boolean) => {
      resetDemoVaultState(state);
      notify('success', t('txt_backup_import_success_relogin'));
      return createDemoImportBackupResult();
    },
    onLoadBackupSettings: async () => state.backupSettings,
    onSaveBackupSettings: async (_masterPassword: string, settings) => {
      const next = cloneJson(settings);
      state.setBackupSettings(next);
      notify('success', t('txt_backup_settings_saved'));
      return next;
    },
    onRunRemoteBackup: async (_masterPassword: string, destinationId?: string | null) => {
      notify('success', t('txt_backup_remote_run_success'));
      return createDemoBackupRun(state.backupSettings, destinationId);
    },
    onListRemoteBackups: async (destinationId: string, path: string) => createDemoRemoteBrowser(destinationId, path),
    onDownloadRemoteBackup: async (_masterPassword: string, _destinationId: string, _path: string, _onProgress?: (percent: number | null) => void) => {
      notify('success', t('txt_demo_download_prepared'));
    },
    onInspectRemoteBackup: async (_masterPassword: string, _destinationId: string, path: string) => ({
      object: 'backup-remote-integrity',
      destinationId: _destinationId,
      path,
      fileName: path.split('/').pop() || 'nodewarden_backup_demo.zip',
      integrity: {
        hasChecksumPrefix: true,
        expectedPrefix: 'a1b2c',
        actualPrefix: 'a1b2c',
        matches: true,
      },
    }),
    onDeleteRemoteBackup: async () => {
      notify('success', t('txt_backup_remote_delete_success'));
    },
    onRestoreRemoteBackup: async (_masterPassword: string, _destinationId, path) => {
      await runDemoRemoteRestoreProgress(path.split('/').pop() || path || 'nodewarden_backup_demo.zip');
      resetDemoVaultState(state);
      notify('success', t('txt_backup_remote_restore_completed_verified'));
      return createDemoImportBackupResult();
    },
    onRestoreRemoteBackupAllowingChecksumMismatch: async (_masterPassword: string, _destinationId, path) => {
      await runDemoRemoteRestoreProgress(path.split('/').pop() || path || 'nodewarden_backup_demo.zip');
      resetDemoVaultState(state);
      notify('success', t('txt_backup_remote_restore_completed_verified'));
      return createDemoImportBackupResult();
    },
  };
}
