import { createPortal } from 'preact/compat';
import { useEffect, useMemo, useState } from 'preact/hooks';
import { Archive, Clipboard, Download, Eye, EyeOff, ExternalLink, Folder, Paperclip, Pencil, RotateCcw, Trash2, X } from 'lucide-preact';
import { useDialogLifecycle } from '@/components/ConfirmDialog';
import type { TotpCodeResult } from '@/lib/crypto';
import type { Cipher } from '@/lib/types';
import { t } from '@/lib/i18n';
import {
  CardBrandIcon,
  TOTP_RING_CIRCUMFERENCE,
  VaultListIcon,
  copyToClipboard,
  displayCardBrand,
  formatAttachmentSize,
  formatHistoryTime,
  formatTotp,
  isCipherDeleted,
  maskSecret,
  openUri,
  parseFieldType,
  toBooleanFieldValue,
} from '@/components/vault/vault-page-helpers';

interface VaultDetailViewProps {
  selectedCipher: Cipher;
  repromptApprovedCipherId: string | null;
  showPassword: boolean;
  totpLive: TotpCodeResult | null;
  passkeyCreatedAt: string | null;
  hiddenFieldVisibleMap: Record<number, boolean>;
  folderName: (id: string | null | undefined) => string;
  downloadingAttachmentKey: string;
  attachmentDownloadPercent: number | null;
  onOpenReprompt: () => void;
  onToggleShowPassword: () => void;
  onToggleHiddenField: (index: number) => void;
  onDownloadAttachment: (cipher: Cipher, attachmentId: string) => void;
  onStartEdit: () => void;
  onDelete: (cipher: Cipher) => void;
  onRestore: (cipher: Cipher) => void | Promise<void>;
  onArchive: (cipher: Cipher) => void | Promise<void>;
  onUnarchive: (cipher: Cipher) => void | Promise<void>;
}

function totpProgress(live: TotpCodeResult | null): number {
  const period = Math.max(1, live?.period || 30);
  return live ? Math.max(0, Math.min(period, live.remain)) / period : 0;
}

function PasswordHistoryDialog(props: {
  open: boolean;
  entries: Array<{ password: string; lastUsedDate: string | null }>;
  onClose: () => void;
}) {
  useDialogLifecycle(props.open, props.onClose);

  if (!props.open || typeof document === 'undefined') return null;
  return createPortal(
    <div className="dialog-mask open" onClick={(event) => event.target === event.currentTarget && props.onClose()}>
      <section className="dialog-card password-history-dialog open" role="dialog" aria-modal="true" aria-label={t('txt_password_history')}>
        <div className="password-history-head">
          <h3 className="dialog-title">{t('txt_password_history')}</h3>
          <button type="button" className="password-history-close" aria-label={t('txt_close')} onClick={props.onClose}>
            <X size={18} />
          </button>
        </div>
        <div className="password-history-list">
          {props.entries.map((entry, index) => (
            <div key={`password-history-${index}-${entry.lastUsedDate || 'none'}`} className="password-history-item">
              <div className="password-history-copy">
                <button type="button" className="btn btn-secondary small password-history-copy-btn" onClick={() => copyToClipboard(entry.password)}>
                  <Clipboard size={16} />
                </button>
              </div>
              <div className="password-history-value">{entry.password}</div>
              <div className="password-history-time">{formatHistoryTime(entry.lastUsedDate)}</div>
            </div>
          ))}
        </div>
        <button type="button" className="btn btn-primary dialog-btn" onClick={props.onClose}>
          {t('txt_close')}
        </button>
      </section>
    </div>,
    document.body
  );
}

export default function VaultDetailView(props: VaultDetailViewProps) {
  const selectedAttachments = Array.isArray(props.selectedCipher.attachments) ? props.selectedCipher.attachments : [];
  const [showSshPrivateKey, setShowSshPrivateKey] = useState(false);
  const [passwordHistoryOpen, setPasswordHistoryOpen] = useState(false);
  const isArchived = !!(props.selectedCipher.archivedDate || (props.selectedCipher as { archivedAt?: string | null }).archivedAt);
  const isDeleted = isCipherDeleted(props.selectedCipher);
  const passwordHistoryEntries = useMemo(
    () =>
      (props.selectedCipher.passwordHistory || [])
        .map((entry) => ({
          password: String(entry?.decPassword || entry?.password || ''),
          lastUsedDate: entry?.lastUsedDate ?? null,
        }))
        .filter((entry) => entry.password.trim()),
    [props.selectedCipher.passwordHistory]
  );
  useEffect(() => {
    setShowSshPrivateKey(false);
    setPasswordHistoryOpen(false);
  }, [props.selectedCipher.id]);
  const formatDownloadLabel = (attachmentId: string) => {
    const downloadKey = `${props.selectedCipher.id}:${attachmentId}`;
    if (props.downloadingAttachmentKey !== downloadKey) return t('txt_download');
    return props.attachmentDownloadPercent == null
      ? t('txt_downloading')
      : t('txt_downloading_percent', { percent: props.attachmentDownloadPercent });
  };

  return (
    <>
      {Number(props.selectedCipher.reprompt || 0) === 1 && props.repromptApprovedCipherId !== props.selectedCipher.id && (
        <div className="card">
          <h4>{t('txt_master_password_reprompt_2')}</h4>
          <div className="detail-sub">{t('txt_this_item_requires_master_password_every_time_before_viewing_details')}</div>
          <div className="actions detail-unlock-actions">
            <button type="button" className="btn btn-primary" onClick={props.onOpenReprompt}>
              <Eye size={14} className="btn-icon" /> {t('txt_unlock_details')}
            </button>
          </div>
        </div>
      )}
      {(Number(props.selectedCipher.reprompt || 0) !== 1 || props.repromptApprovedCipherId === props.selectedCipher.id) && (
        <>
          <div className="card">
            <div className="detail-title-row">
              <span className="detail-title-icon" aria-hidden="true">
                <VaultListIcon cipher={props.selectedCipher} />
              </span>
              <div className="detail-title-main">
                <h3 className="detail-title">{props.selectedCipher.decName || t('txt_no_name')}</h3>
                <div className="detail-folder-line">
                  <Folder size={13} aria-hidden="true" />
                  <span>{props.folderName(props.selectedCipher.folderId)}</span>
                </div>
              </div>
            </div>
            {isArchived && <div className="list-badge archive-badge">{t('txt_archived')}</div>}
          </div>

          {props.selectedCipher.login && (
            <div className="card">
              <h4>{t('txt_login_credentials')}</h4>
              <div className="kv-row">
                <span className="kv-label">{t('txt_username')}</span>
                <div className="kv-main">
                  <strong className="value-ellipsis" title={props.selectedCipher.login.decUsername || ''}>{props.selectedCipher.login.decUsername || ''}</strong>
                </div>
                <div className="kv-actions">
                  <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(props.selectedCipher.login?.decUsername || '')}>
                    <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                  </button>
                </div>
              </div>
              <div className="kv-row">
                <span className="kv-label">{t('txt_password')}</span>
                <div className="kv-main">
                  <strong>{props.showPassword ? props.selectedCipher.login.decPassword || '' : maskSecret(props.selectedCipher.login.decPassword || '')}</strong>
                </div>
                <div className="kv-actions">
                  <button type="button" className="btn btn-secondary small" onClick={props.onToggleShowPassword}>
                    {props.showPassword ? <EyeOff size={14} className="btn-icon" /> : <Eye size={14} className="btn-icon" />}
                    {props.showPassword ? t('txt_hide') : t('txt_reveal')}
                  </button>
                  <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(props.selectedCipher.login?.decPassword || '')}>
                    <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                  </button>
                </div>
              </div>
              {!!props.selectedCipher.login.decTotp && (
                <div className="kv-row">
                  <span className="kv-label">{t('txt_totp')}</span>
                  <div className="kv-main">
                    <div className="totp-inline">
                      <strong>{props.totpLive ? formatTotp(props.totpLive.code) : t('txt_text_3')}</strong>
                      <div
                        className="totp-timer"
                        title={t('txt_refresh_in_seconds_s', { seconds: props.totpLive ? props.totpLive.remain : 0 })}
                        aria-label={t('txt_refresh_in_seconds_s', { seconds: props.totpLive ? props.totpLive.remain : 0 })}
                      >
                        <svg viewBox="0 0 36 36" className="totp-ring" role="presentation" aria-hidden="true">
                          <circle className="totp-ring-track" cx="18" cy="18" r="15.9155" />
                          <circle
                            className="totp-ring-progress"
                            cx="18"
                            cy="18"
                            r="15.9155"
                            style={{
                              strokeDasharray: `${TOTP_RING_CIRCUMFERENCE} ${TOTP_RING_CIRCUMFERENCE}`,
                              strokeDashoffset: String(
                                TOTP_RING_CIRCUMFERENCE -
                                  TOTP_RING_CIRCUMFERENCE * totpProgress(props.totpLive)
                              ),
                            }}
                          />
                        </svg>
                        <span className="totp-timer-value">{props.totpLive ? props.totpLive.remain : 0}</span>
                      </div>
                    </div>
                  </div>
                  <div className="kv-actions">
                    <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(props.totpLive?.code || '')}>
                      <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                    </button>
                  </div>
                </div>
              )}
              {!!props.passkeyCreatedAt && (
                <div className="kv-row">
                  <span className="kv-label">{t('txt_passkey')}</span>
                  <div className="kv-main">
                    <strong>{t('txt_passkey_created_at_value', { value: formatHistoryTime(props.passkeyCreatedAt) })}</strong>
                  </div>
                  <div className="kv-actions" />
                </div>
              )}
            </div>
          )}

          {(props.selectedCipher.login?.uris || []).length > 0 && (
            <div className="card">
              <h4>{t('txt_autofill_options')}</h4>
              {(props.selectedCipher.login?.uris || []).map((uri, index) => {
                const value = uri.decUri || uri.uri || '';
                if (!value.trim()) return null;
                return (
                  <div key={`view-uri-${index}`} className="kv-row">
                    <span className="kv-label">{t('txt_website')}</span>
                    <div className="kv-main">
                      <strong className="value-ellipsis" title={value}>{value}</strong>
                    </div>
                    <div className="kv-actions">
                      <button type="button" className="btn btn-secondary small" onClick={() => openUri(value)}>
                        <ExternalLink size={14} className="btn-icon" /> {t('txt_open')}
                      </button>
                      <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(value)}>
                        <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {props.selectedCipher.card && (
            <div className="card">
              <h4>{t('txt_card_details')}</h4>
              <div className="kv-line"><span>{t('txt_cardholder_name')}</span><strong>{props.selectedCipher.card.decCardholderName || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_number')}</span><strong>{props.selectedCipher.card.decNumber || ''}</strong></div>
              <div className="kv-line">
                <span>{t('txt_brand')}</span>
                <strong className="card-brand-detail">
                  <CardBrandIcon brand={props.selectedCipher.card.decBrand} />
                  {displayCardBrand(props.selectedCipher.card.decBrand)}
                </strong>
              </div>
              <div className="kv-line"><span>{t('txt_expiry')}</span><strong>{`${props.selectedCipher.card.decExpMonth || ''}/${props.selectedCipher.card.decExpYear || ''}`}</strong></div>
              <div className="kv-line"><span>{t('txt_security_code')}</span><strong>{props.selectedCipher.card.decCode || ''}</strong></div>
            </div>
          )}

          {props.selectedCipher.identity && (
            <div className="card">
              <h4>{t('txt_identity_details')}</h4>
              <div className="kv-line"><span>{t('txt_name')}</span><strong>{`${props.selectedCipher.identity.decFirstName || ''} ${props.selectedCipher.identity.decLastName || ''}`.trim()}</strong></div>
              <div className="kv-line"><span>{t('txt_username')}</span><strong>{props.selectedCipher.identity.decUsername || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_email')}</span><strong>{props.selectedCipher.identity.decEmail || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_phone')}</span><strong>{props.selectedCipher.identity.decPhone || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_company')}</span><strong>{props.selectedCipher.identity.decCompany || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_address')}</span><strong>{[props.selectedCipher.identity.decAddress1, props.selectedCipher.identity.decAddress2, props.selectedCipher.identity.decAddress3, props.selectedCipher.identity.decCity, props.selectedCipher.identity.decState, props.selectedCipher.identity.decPostalCode, props.selectedCipher.identity.decCountry].filter(Boolean).join(', ')}</strong></div>
            </div>
          )}

          {props.selectedCipher.sshKey && (
            <div className="card">
              <h4>{t('txt_ssh_key')}</h4>
              <div className="kv-row">
                <span className="kv-label">{t('txt_private_key')}</span>
                <div className="kv-main">
                  <strong
                    className="value-ellipsis"
                    title={showSshPrivateKey ? props.selectedCipher.sshKey.decPrivateKey || '' : maskSecret(props.selectedCipher.sshKey.decPrivateKey || '')}
                  >
                    {showSshPrivateKey ? props.selectedCipher.sshKey.decPrivateKey || '' : maskSecret(props.selectedCipher.sshKey.decPrivateKey || '')}
                  </strong>
                </div>
                <div className="kv-actions">
                  <button type="button" className="btn btn-secondary small" onClick={() => setShowSshPrivateKey((value) => !value)}>
                    {showSshPrivateKey ? <EyeOff size={14} className="btn-icon" /> : <Eye size={14} className="btn-icon" />}
                    {showSshPrivateKey ? t('txt_hide') : t('txt_reveal')}
                  </button>
                  <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(props.selectedCipher.sshKey?.decPrivateKey || '')}>
                    <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                  </button>
                </div>
              </div>
              <div className="kv-row">
                <span className="kv-label">{t('txt_public_key')}</span>
                <div className="kv-main">
                  <strong className="value-ellipsis" title={props.selectedCipher.sshKey.decPublicKey || ''}>
                    {props.selectedCipher.sshKey.decPublicKey || ''}
                  </strong>
                </div>
                <div className="kv-actions">
                  <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(props.selectedCipher.sshKey?.decPublicKey || '')}>
                    <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                  </button>
                </div>
              </div>
              <div className="kv-row">
                <span className="kv-label">{t('txt_fingerprint')}</span>
                <div className="kv-main">
                  <strong className="value-ellipsis" title={props.selectedCipher.sshKey.decFingerprint || ''}>
                    {props.selectedCipher.sshKey.decFingerprint || ''}
                  </strong>
                </div>
                <div className="kv-actions">
                  <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(props.selectedCipher.sshKey?.decFingerprint || '')}>
                    <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                  </button>
                </div>
              </div>
            </div>
          )}

          {props.selectedCipher.bankAccount && (
            <div className="card">
              <h4>{t('txt_bank_account_details')}</h4>
              <div className="kv-line"><span>{t('txt_bank_name')}</span><strong>{props.selectedCipher.bankAccount.decBankName || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_name_on_account')}</span><strong>{props.selectedCipher.bankAccount.decNameOnAccount || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_account_type')}</span><strong>{props.selectedCipher.bankAccount.decAccountType || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_account_number')}</span><strong>{props.selectedCipher.bankAccount.decAccountNumber || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_routing_number')}</span><strong>{props.selectedCipher.bankAccount.decRoutingNumber || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_branch_number')}</span><strong>{props.selectedCipher.bankAccount.decBranchNumber || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_pin')}</span><strong>{props.selectedCipher.bankAccount.decPin || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_swift_code')}</span><strong>{props.selectedCipher.bankAccount.decSwiftCode || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_iban')}</span><strong>{props.selectedCipher.bankAccount.decIban || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_bank_contact_phone')}</span><strong>{props.selectedCipher.bankAccount.decBankContactPhone || ''}</strong></div>
            </div>
          )}

          {props.selectedCipher.driversLicense && (
            <div className="card">
              <h4>{t('txt_drivers_license_details')}</h4>
              <div className="kv-line"><span>{t('txt_name')}</span><strong>{[props.selectedCipher.driversLicense.decFirstName, props.selectedCipher.driversLicense.decMiddleName, props.selectedCipher.driversLicense.decLastName].filter(Boolean).join(' ')}</strong></div>
              <div className="kv-line"><span>{t('txt_date_of_birth')}</span><strong>{props.selectedCipher.driversLicense.decDateOfBirth || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_license_number')}</span><strong>{props.selectedCipher.driversLicense.decLicenseNumber || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_issuing_country')}</span><strong>{props.selectedCipher.driversLicense.decIssuingCountry || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_issuing_state')}</span><strong>{props.selectedCipher.driversLicense.decIssuingState || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_issue_date')}</span><strong>{props.selectedCipher.driversLicense.decIssueDate || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_expiration_date')}</span><strong>{props.selectedCipher.driversLicense.decExpirationDate || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_issuing_authority')}</span><strong>{props.selectedCipher.driversLicense.decIssuingAuthority || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_license_class')}</span><strong>{props.selectedCipher.driversLicense.decLicenseClass || ''}</strong></div>
            </div>
          )}

          {props.selectedCipher.passport && (
            <div className="card">
              <h4>{t('txt_passport_details')}</h4>
              <div className="kv-line"><span>{t('txt_name')}</span><strong>{[props.selectedCipher.passport.decGivenName, props.selectedCipher.passport.decSurname].filter(Boolean).join(' ')}</strong></div>
              <div className="kv-line"><span>{t('txt_date_of_birth')}</span><strong>{props.selectedCipher.passport.decDateOfBirth || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_sex')}</span><strong>{props.selectedCipher.passport.decSex || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_birth_place')}</span><strong>{props.selectedCipher.passport.decBirthPlace || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_nationality')}</span><strong>{props.selectedCipher.passport.decNationality || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_issuing_country')}</span><strong>{props.selectedCipher.passport.decIssuingCountry || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_passport_number')}</span><strong>{props.selectedCipher.passport.decPassportNumber || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_passport_type')}</span><strong>{props.selectedCipher.passport.decPassportType || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_national_id_number')}</span><strong>{props.selectedCipher.passport.decNationalIdentificationNumber || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_issuing_authority')}</span><strong>{props.selectedCipher.passport.decIssuingAuthority || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_issue_date')}</span><strong>{props.selectedCipher.passport.decIssueDate || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_expiration_date')}</span><strong>{props.selectedCipher.passport.decExpirationDate || ''}</strong></div>
            </div>
          )}

          {!!(props.selectedCipher.decNotes || '').trim() && (
            <div className="card">
              <h4>{t('txt_notes')}</h4>
              <div className="notes">{props.selectedCipher.decNotes || ''}</div>
            </div>
          )}

          {(props.selectedCipher.fields || []).some((x) => parseFieldType(x.type) !== 3) && (
            <div className="card">
              <h4>{t('txt_custom_fields')}</h4>
              {(props.selectedCipher.fields || [])
                .filter((x) => parseFieldType(x.type) !== 3)
                .map((field, index) => {
                  const fieldType = parseFieldType(field.type);
                  const fieldName = field.decName || t('txt_field');
                  const rawValue = field.decValue || '';
                  const isHiddenVisible = !!props.hiddenFieldVisibleMap[index];
                  if (fieldType === 2) {
                    const checked = toBooleanFieldValue(rawValue);
                    return (
                      <div key={`view-field-${index}`} className="custom-field-card">
                        <div className="custom-field-label">{fieldName}</div>
                        <div className="custom-field-body">
                          <div className="custom-field-value">
                            <label className="check-line cf-check view custom-field-check">
                              <input type="checkbox" checked={checked} disabled />
                              <span className="boolean-text value-ellipsis" title={checked ? t('txt_checked') : t('txt_unchecked')}>
                                {checked ? t('txt_checked') : t('txt_unchecked')}
                              </span>
                            </label>
                          </div>
                          <div className="kv-actions">
                            <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(rawValue)}>
                              <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                            </button>
                          </div>
                        </div>
                      </div>
                    );
                  }
                  return (
                    <div key={`view-field-${index}`} className="custom-field-card">
                      <div className="custom-field-label" title={fieldName}>{fieldName}</div>
                      <div className="custom-field-body">
                        <div className="custom-field-value">
                          <strong
                            className={fieldType === 1 && !isHiddenVisible ? 'value-ellipsis' : 'custom-field-display'}
                            title={fieldType === 1 && !isHiddenVisible ? '' : rawValue}
                          >
                            {fieldType === 1 && !isHiddenVisible ? maskSecret(rawValue) : rawValue}
                          </strong>
                        </div>
                        <div className="kv-actions">
                        {fieldType === 1 && (
                          <button type="button" className="btn btn-secondary small" onClick={() => props.onToggleHiddenField(index)}>
                            {isHiddenVisible ? <EyeOff size={14} className="btn-icon" /> : <Eye size={14} className="btn-icon" />}
                            {isHiddenVisible ? t('txt_hide') : t('txt_reveal')}
                          </button>
                        )}
                        <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(rawValue)}>
                          <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                        </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
            </div>
          )}

          {selectedAttachments.some((attachment) => String(attachment?.id || '').trim()) && (
            <div className="card">
              <h4>{t('txt_attachments')}</h4>
              <div className="attachment-list">
                {selectedAttachments.map((attachment) => {
                  const attachmentId = String(attachment?.id || '').trim();
                  if (!attachmentId) return null;
                  const fileName = String(attachment.decFileName || attachment.fileName || attachmentId).trim() || attachmentId;
                  return (
                    <div key={`view-attachment-${attachmentId}`} className="attachment-row">
                      <div className="attachment-main">
                        <Paperclip size={14} />
                        <div className="attachment-text">
                          <strong className="value-ellipsis" title={fileName}>{fileName}</strong>
                          <span>{formatAttachmentSize(attachment)}</span>
                        </div>
                      </div>
                      <div className="kv-actions">
                        <button
                          type="button"
                          className="btn btn-secondary small"
                          disabled={props.downloadingAttachmentKey === `${props.selectedCipher.id}:${attachmentId}`}
                          onClick={() => props.onDownloadAttachment(props.selectedCipher, attachmentId)}
                        >
                          <Download size={14} className="btn-icon" /> {formatDownloadLabel(attachmentId)}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {(props.selectedCipher.creationDate || props.selectedCipher.revisionDate) && (
            <div className="card">
              <h4>{t('txt_item_history')}</h4>
              <div className="detail-sub">{t('txt_last_edited_value', { value: formatHistoryTime(props.selectedCipher.revisionDate) })}</div>
              <div className="detail-sub">{t('txt_created_value', { value: formatHistoryTime(props.selectedCipher.creationDate) })}</div>
              {!!props.selectedCipher.login?.passwordRevisionDate && (
                <div className="detail-sub">{t('txt_password_updated_value', { value: formatHistoryTime(props.selectedCipher.login.passwordRevisionDate) })}</div>
              )}
              {passwordHistoryEntries.length > 0 && (
                <button type="button" className="password-history-link" onClick={() => setPasswordHistoryOpen(true)}>
                  {t('txt_password_history')}
                </button>
              )}
            </div>
          )}

          <div className="detail-actions">
            <div className="actions">
              {isDeleted ? (
                <button type="button" className="btn btn-secondary" onClick={() => void props.onRestore(props.selectedCipher)}>
                  <RotateCcw size={14} className="btn-icon" /> {t('txt_restore')}
                </button>
              ) : (
                <>
                  <button type="button" className="btn btn-secondary" onClick={props.onStartEdit}>
                    <Pencil size={14} className="btn-icon" /> {t('txt_edit')}
                  </button>
                  {isArchived ? (
                    <button type="button" className="btn btn-secondary" onClick={() => void props.onUnarchive(props.selectedCipher)}>
                      <RotateCcw size={14} className="btn-icon" /> {t('txt_unarchive')}
                    </button>
                  ) : (
                    <button type="button" className="btn btn-secondary" onClick={() => void props.onArchive(props.selectedCipher)}>
                      <Archive size={14} className="btn-icon" /> {t('txt_archive')}
                    </button>
                  )}
                </>
              )}
            </div>
            <button type="button" className="btn btn-danger" onClick={() => props.onDelete(props.selectedCipher)}>
              <Trash2 size={14} className="btn-icon" /> {isDeleted ? t('txt_delete_permanently') : t('txt_delete')}
            </button>
          </div>
        </>
      )}
      <PasswordHistoryDialog
        open={passwordHistoryOpen}
        entries={passwordHistoryEntries}
        onClose={() => setPasswordHistoryOpen(false)}
      />
    </>
  );
}
