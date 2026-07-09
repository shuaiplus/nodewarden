// CONTRACT:
// Locale bundles are standalone and loaded on demand. Adding a locale requires
// updating Locale, AVAILABLE_LOCALES, browser-language detection, localeLoaders,
// scripts/i18n-utils.cjs, and the locale file itself.
//
// Do not call t() at module scope for exported arrays/constants; async init can
// otherwise leave raw txt_* keys in the rendered UI.
export type Locale =
  | 'en'
  | 'zh-CN'
  | 'zh-TW'
  | 'ru'
  | 'es'
  | 'fi';

import enMessages from './i18n/locales/en';
const LOCALE_STORAGE_KEY = 'nodewarden.locale';

type MessageTable = Record<string, string>;

export const AVAILABLE_LOCALES: readonly { value: Locale; label: string }[] = [
  { value: 'en', label: 'English' },
  { value: 'zh-CN', label: '简体中文' },
  { value: 'zh-TW', label: '繁體中文' },
  { value: 'ru', label: 'Русский' },
  { value: 'es', label: 'Español' },
  { value: 'fi', label: 'Suomi' },
];

let locale: Locale = resolveInitialLocale();
let activeMessages: MessageTable = enMessages;
const loadedMessages = new Map<Locale, MessageTable>([['en', enMessages]]);

function isLocale(value: unknown): value is Locale {
  return AVAILABLE_LOCALES.some((item) => item.value === value);
}

function resolveInitialLocale(): Locale {
  try {
    const saved = localStorage.getItem(LOCALE_STORAGE_KEY);
    if (isLocale(saved)) return saved;
  } catch {
    // ignore storage errors
  }
  if (typeof navigator !== 'undefined') {
    const langs = Array.isArray(navigator.languages) ? navigator.languages : [navigator.language];
    for (const lang of langs) {
      const normalized = String(lang || '').toLowerCase();
      if (normalized === 'zh-tw' || normalized === 'zh-hk' || normalized === 'zh-mo' || normalized.includes('hant')) return 'zh-TW';
      if (normalized.startsWith('zh')) return 'zh-CN';
      if (normalized.startsWith('ru')) return 'ru';
      if (normalized.startsWith('es')) return 'es';
      if (normalized.startsWith('fi')) return 'fi';
    }
  }
  return 'en';
}

const localeLoaders: Record<Locale, () => Promise<{ default: MessageTable }>> = {
  en: () => Promise.resolve({ default: enMessages }),
  'zh-CN': () => import('./i18n/locales/zh-CN'),
  'zh-TW': () => import('./i18n/locales/zh-TW'),
  ru: () => import('./i18n/locales/ru'),
  es: () => import('./i18n/locales/es'),
  fi: () => import('./i18n/locales/fi'),
};

function localeToHtmlLang(value: Locale): string {
  return value;
}

function syncDocumentLanguage(): void {
  if (typeof document === 'undefined') return;
  document.documentElement.lang = localeToHtmlLang(locale);
}

async function loadLocaleMessages(next: Locale): Promise<MessageTable> {
  const cached = loadedMessages.get(next);
  if (cached) return cached;
  const mod = await localeLoaders[next]();
  loadedMessages.set(next, mod.default);
  return mod.default;
}

async function loadFallbackMessages(): Promise<MessageTable> {
  return enMessages;
}

export type I18nParams = Record<string, string | number | null | undefined>;

export async function initI18n(): Promise<void> {
  try {
    activeMessages = await loadLocaleMessages(locale);
  } catch (error) {
    console.error('Failed to load locale, falling back to English:', error);
    locale = 'en';
    activeMessages = await loadFallbackMessages();
  } finally {
    syncDocumentLanguage();
  }
}

export function t(key: string, params?: I18nParams): string {
  const template = activeMessages[key] ?? key;
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (_, name: string) => String(params[name] ?? ''));
}

export function translateServerError(message: string | null | undefined, fallback: string): string {
  const normalized = String(message || '').trim();
  if (!normalized) return fallback;

  const rateLimitMatch = normalized.match(/^Rate limit exceeded\. Try again in (\d+) seconds\.$/i);
  if (rateLimitMatch) {
    return t('txt_rate_limit_try_again_seconds', { seconds: rateLimitMatch[1] });
  }

  const backupDestinationLimitMatch = normalized.match(/^You can save up to (\d+) backup destinations$/i);
  if (backupDestinationLimitMatch) {
    return t('txt_backup_error_destination_limit', { count: backupDestinationLimitMatch[1] });
  }

  const backupArchiveVerificationMatch = normalized.match(/^Backup archive upload verification failed after (\d+) attempts: (.+)$/i);
  if (backupArchiveVerificationMatch) {
    return t('txt_backup_error_archive_upload_verification_failed_attempts', {
      count: backupArchiveVerificationMatch[1],
      reason: translateServerError(backupArchiveVerificationMatch[2], backupArchiveVerificationMatch[2]),
    });
  }

  const remoteAttachmentStatusMatch = normalized.match(/^Remote attachment (download|batch download) failed: (\d+)$/i);
  if (remoteAttachmentStatusMatch) {
    return t(
      remoteAttachmentStatusMatch[1].toLowerCase() === 'batch download'
        ? 'txt_backup_error_remote_attachment_batch_download_failed_status'
        : 'txt_backup_error_remote_attachment_download_failed_status',
      { status: remoteAttachmentStatusMatch[2] }
    );
  }

  const providerStatusMatch = normalized.match(/^(WebDAV|S3) (directory creation|upload|listing|download|delete|existence check) failed: (\d+)$/i);
  if (providerStatusMatch) {
    const provider = providerStatusMatch[1].toLowerCase() === 'webdav' ? 'webdav' : 's3';
    const actionKey = providerStatusMatch[2].toLowerCase().replace(/\s+/g, '_');
    return t(`txt_backup_error_${provider}_${actionKey}_failed_status`, { status: providerStatusMatch[3] });
  }

  const key = {
    'Account is disabled': 'txt_server_error_account_disabled',
    'Another backup or restore run is already in progress': 'txt_backup_error_another_backup_or_restore_running',
    'Another backup run is already in progress': 'txt_backup_error_another_backup_running',
    'Backup archive upload failed': 'txt_backup_error_archive_upload_failed',
    'Backup attachment blob is invalid': 'txt_backup_error_attachment_blob_invalid',
    'Backup attachment blob is required': 'txt_backup_error_attachment_blob_required',
    'Backup attachment blob not found': 'txt_backup_error_attachment_blob_not_found',
    'Backup attachment download failed': 'txt_backup_error_attachment_download_failed',
    'Backup destination is invalid': 'txt_backup_error_destination_invalid',
    'Backup destination not found': 'txt_backup_error_destination_not_found',
    'Backup destination ids must be unique': 'txt_backup_error_destination_ids_unique',
    'Backup destination type is invalid': 'txt_backup_error_destination_type_invalid',
    'Backup destinations are invalid': 'txt_backup_error_destinations_invalid',
    'Backup export payload is invalid': 'txt_backup_error_export_payload_invalid',
    'Backup file checksum does not match its filename': 'txt_backup_error_file_checksum_mismatch',
    'Backup file is required': 'txt_backup_error_file_required',
    'Backup interval hours must be between 1 and 99': 'txt_backup_error_interval_hours_range',
    'Backup retention count must be between 1 and 1000': 'txt_backup_error_retention_count_range',
    'Backup run failed': 'txt_backup_error_run_failed',
    'Backup run payload is invalid': 'txt_backup_error_run_payload_invalid',
    'Backup run response is invalid': 'txt_backup_error_run_response_invalid',
    'Backup settings are invalid': 'txt_backup_error_settings_invalid',
    'Backup settings could not be loaded': 'txt_backup_error_settings_load_failed',
    'Backup settings envelope is invalid': 'txt_backup_error_settings_envelope_invalid',
    'Backup settings need administrator reactivation after restore': 'txt_backup_error_settings_need_reactivation',
    'Backup settings payload is invalid': 'txt_backup_error_settings_payload_invalid',
    'Backup settings repair payload is invalid': 'txt_backup_error_settings_repair_payload_invalid',
    'Backup settings repair state could not be loaded': 'txt_backup_error_settings_repair_state_load_failed',
    'Backup start time must be in HH:mm format': 'txt_backup_error_start_time_format',
    'Client IP is required': 'txt_server_error_client_ip_required',
    'ClientId or clientSecret is incorrect. Try again': 'txt_server_error_client_credentials_incorrect',
    'Content-Type must be multipart/form-data': 'txt_backup_error_multipart_required',
    'Email already registered': 'txt_server_error_email_already_registered',
    'Email and password are required': 'txt_server_error_email_password_required',
    'Email is required': 'txt_server_error_email_required',
    'Forbidden': 'txt_server_error_forbidden',
    'Invite code is invalid or expired': 'txt_server_error_invite_invalid_or_expired',
    'Invite code is required': 'txt_server_error_invite_required',
    'Invalid backup timezone': 'txt_backup_error_timezone_invalid',
    'Invalid password': 'txt_server_error_invalid_password',
    'Invalid refresh token': 'txt_server_error_invalid_refresh_token',
    'Invalid remote backup path': 'txt_backup_error_remote_path_invalid',
    'Invalid request payload': 'txt_server_error_invalid_request_payload',
    'Invalid user verification token': 'txt_server_error_invalid_user_verification_token',
    'JWT_SECRET is not set': 'txt_server_error_jwt_secret_missing',
    'JWT_SECRET is using the default/sample value. Please change it.': 'txt_server_error_jwt_secret_default',
    'JWT_SECRET must be at least 32 characters': 'txt_server_error_jwt_secret_too_short',
    'Parameter error': 'txt_server_error_parameter_error',
    'Please select a backup file': 'txt_backup_error_select_backup_file',
    'Please select a backup ZIP file': 'txt_backup_error_select_backup_zip_file',
    'Refresh token is required': 'txt_server_error_refresh_token_required',
    'Remote backup ZIP checksum verification failed': 'txt_backup_error_remote_zip_checksum_failed',
    'Remote backup ZIP size verification failed': 'txt_backup_error_remote_zip_size_failed',
    'Remote backup delete failed': 'txt_backup_error_remote_delete_failed',
    'Remote backup download failed': 'txt_backup_error_remote_download_failed',
    'Remote backup download payload is invalid': 'txt_backup_error_remote_download_payload_invalid',
    'Remote backup integrity inspection failed': 'txt_backup_error_remote_integrity_failed',
    'Remote backup listing failed': 'txt_backup_error_remote_listing_failed',
    'Remote restore payload is invalid': 'txt_backup_error_remote_restore_payload_invalid',
    'Registration is temporarily unavailable, retry once': 'txt_server_error_registration_retry',
    'S3 access key is required': 'txt_backup_error_s3_access_key_required',
    'S3 bucket is required': 'txt_backup_error_s3_bucket_required',
    'S3 endpoint is required': 'txt_backup_error_s3_endpoint_required',
    'S3 endpoint must start with http:// or https://': 'txt_backup_error_s3_endpoint_protocol',
    'S3 secret key is required': 'txt_backup_error_s3_secret_key_required',
    'TOTP token is required': 'txt_server_error_totp_token_required',
    'Two factor required.': 'txt_server_error_two_factor_required',
    'Two-step token is invalid. Try again.': 'txt_server_error_two_factor_invalid',
    'Unable to read backup file': 'txt_backup_error_read_backup_file_failed',
    'Unsupported backup destination type': 'txt_backup_error_destination_type_unsupported',
    'Username or password is incorrect. Try again': 'txt_server_error_username_password_incorrect',
    'WebDAV password is required': 'txt_backup_error_webdav_password_required',
    'WebDAV remote backup path is too deep for safe attachment batching': 'txt_backup_error_webdav_path_too_deep',
    'WebDAV server URL is required': 'txt_backup_error_webdav_url_required',
    'WebDAV server URL must start with http:// or https://': 'txt_backup_error_webdav_url_protocol',
    'WebDAV username is required': 'txt_backup_error_webdav_username_required',
    'masterPasswordHash is required': 'txt_server_error_master_password_hash_required',
    'masterPasswordHash or userVerificationToken is required': 'txt_server_error_master_password_or_verification_required',
  }[normalized];
  return key ? t(key) : normalized;
}

export function getLocale(): Locale {
  return locale;
}

export async function setLocale(next: Locale): Promise<void> {
  let nextMessages: MessageTable;
  try {
    nextMessages = await loadLocaleMessages(next);
  } catch (error) {
    console.error('Failed to load selected locale, falling back to English:', error);
    next = 'en';
    nextMessages = await loadFallbackMessages();
  }
  locale = next;
  activeMessages = nextMessages;
  syncDocumentLanguage();
  try {
    localStorage.setItem(LOCALE_STORAGE_KEY, next);
  } catch {
    // ignore storage errors
  }
}
