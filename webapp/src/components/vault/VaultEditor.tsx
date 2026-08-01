import type { RefObject } from 'preact';
import { createPortal } from 'preact/compat';
import { ArrowDown, ArrowUp, CheckCheck, Download, Paperclip, Plus, QrCode, RefreshCw, Star, StarOff, Trash2, Upload, X } from 'lucide-preact';
import jsQR from 'jsqr';
import { useEffect, useRef, useState } from 'preact/hooks';
import { useDialogLifecycle } from '@/components/ConfirmDialog';
import { normalizeTotpInput } from '@/lib/crypto';
import type { Cipher, Folder, VaultDraft, VaultDraftField } from '@/lib/types';
import { t } from '@/lib/i18n';
import { cardBrand } from '@/lib/import-format-shared';
import {
  CARD_BRAND_OPTIONS,
  CardBrandIcon,
  cipherTypeLabel,
  createEmptyLoginUri,
  formatAttachmentSize,
  formatHistoryTime,
  getCreateTypeOptions,
  getWebsiteMatchOptions,
  normalizeCardBrand,
  toBooleanFieldValue,
} from '@/components/vault/vault-page-helpers';

interface VaultEditorProps {
  draft: VaultDraft;
  isCreating: boolean;
  busy: boolean;
  folders: Folder[];
  selectedCipher: Cipher | null;
  editExistingAttachments: Array<any>;
  removedAttachmentIds: Record<string, boolean>;
  removedAttachmentCount: number;
  attachmentQueue: File[];
  attachmentInputRef: RefObject<HTMLInputElement>;
  localError: string;
  downloadingAttachmentKey: string;
  attachmentDownloadPercent: number | null;
  uploadingAttachmentName: string;
  attachmentUploadPercent: number | null;
  onUpdateDraft: (patch: Partial<VaultDraft>) => void;
  onSeedSshDefaults: (force?: boolean) => void;
  onUpdateSshPublicKey: (value: string) => void;
  onUpdateDraftLoginUri: (index: number, value: string) => void;
  onUpdateDraftLoginUriMatch: (index: number, value: number | null) => void;
  onReorderDraftLoginUri: (fromIndex: number, toIndex: number) => void;
  onRequestDeleteLoginPasskey: (index: number) => void;
  onQueueAttachmentFiles: (list: FileList | null) => void;
  onToggleExistingAttachmentRemoval: (attachmentId: string) => void;
  onRemoveQueuedAttachment: (index: number) => void;
  onDownloadAttachment: (cipher: Cipher, attachmentId: string) => void;
  onPatchDraftCustomField: (index: number, patch: Partial<VaultDraftField>) => void;
  onUpdateDraftCustomFields: (fields: VaultDraftField[]) => void;
  onOpenFieldModal: () => void;
  onSave: () => void;
  onCancel: () => void;
  onDeleteSelected: () => void;
}

interface WebsiteRowProps {
  uriEntry: VaultDraft['loginUris'][number];
  index: number;
  canRemove: boolean;
  canMoveUp: boolean;
  canMoveDown: boolean;
  onUpdateUri: (index: number, value: string) => void;
  onUpdateMatch: (index: number, value: number | null) => void;
  onMove: (fromIndex: number, toIndex: number) => void;
  onRemove: (index: number) => void;
}

const TOTP_QR_IMAGE_MAX_BYTES = 8 * 1024 * 1024;

function WebsiteRow(props: WebsiteRowProps) {
  const websiteMatchOptions = getWebsiteMatchOptions();

  return (
    <div className="website-row">
      <div className="website-order-actions">
        <button
          type="button"
          className="btn btn-secondary small website-order-btn"
          title={t('txt_move_up')}
          aria-label={t('txt_move_up')}
          disabled={!props.canMoveUp}
          onClick={() => props.onMove(props.index, props.index - 1)}
        >
          <ArrowUp size={14} className="btn-icon" />
        </button>
        <button
          type="button"
          className="btn btn-secondary small website-order-btn"
          title={t('txt_move_down')}
          aria-label={t('txt_move_down')}
          disabled={!props.canMoveDown}
          onClick={() => props.onMove(props.index, props.index + 1)}
        >
          <ArrowDown size={14} className="btn-icon" />
        </button>
      </div>
      <input
        className="input"
        value={props.uriEntry.uri}
        onInput={(e) => props.onUpdateUri(props.index, (e.currentTarget as HTMLInputElement).value)}
      />
      <select
        className="input website-match-select"
        value={props.uriEntry.match == null ? '' : String(props.uriEntry.match)}
        onInput={(e) => {
          const raw = (e.currentTarget as HTMLSelectElement).value;
          props.onUpdateMatch(props.index, raw === '' ? null : Number(raw));
        }}
      >
        {websiteMatchOptions.map((option) => (
          <option key={`website-match-${String(option.value)}`} value={option.value == null ? '' : String(option.value)}>
            {option.label}
          </option>
        ))}
      </select>
      {props.canRemove && (
        <button
          type="button"
          className="btn btn-secondary small website-remove-btn"
          title={t('txt_remove')}
          aria-label={t('txt_remove')}
          onClick={() => props.onRemove(props.index)}
        >
          <X size={14} className="btn-icon" />
          {t('txt_remove')}
        </button>
      )}
    </div>
  );
}

export default function VaultEditor(props: VaultEditorProps) {
  const createTypeOptions = getCreateTypeOptions();
  const normalizedDraftCardBrand = normalizeCardBrand(props.draft.cardBrand);
  const cardBrandOptions = normalizedDraftCardBrand && !CARD_BRAND_OPTIONS.includes(normalizedDraftCardBrand as any)
    ? [...CARD_BRAND_OPTIONS, normalizedDraftCardBrand]
    : CARD_BRAND_OPTIONS;
  const totpQrVideoRef = useRef<HTMLVideoElement | null>(null);
  const totpQrFileRef = useRef<HTMLInputElement | null>(null);
  const totpQrStreamRef = useRef<MediaStream | null>(null);
  const totpQrFrameRef = useRef<number | null>(null);
  const [totpQrOpen, setTotpQrOpen] = useState(false);
  const [totpQrStatus, setTotpQrStatus] = useState('');
  const [totpQrBusy, setTotpQrBusy] = useState(false);
  useDialogLifecycle(totpQrOpen, () => setTotpQrOpen(false));

  const stopTotpQrScanner = () => {
    if (totpQrFrameRef.current != null) {
      window.cancelAnimationFrame(totpQrFrameRef.current);
      totpQrFrameRef.current = null;
    }
    if (totpQrStreamRef.current) {
      for (const track of totpQrStreamRef.current.getTracks()) track.stop();
      totpQrStreamRef.current = null;
    }
    if (totpQrVideoRef.current) {
      totpQrVideoRef.current.srcObject = null;
    }
  };

  const applyTotpQrValue = (value: string) => {
    const normalized = normalizeTotpInput(value);
    if (!normalized) return false;
    props.onUpdateDraft({ loginTotp: normalized });
    setTotpQrStatus(t('txt_totp_qr_scanned'));
    setTotpQrOpen(false);
    return true;
  };

  const createTotpQrDetector = (): BarcodeDetector | null => {
    if (typeof window === 'undefined' || !window.BarcodeDetector) return null;
    return new window.BarcodeDetector({ formats: ['qr_code'] });
  };

  const decodeTotpQrCanvas = (source: ImageBitmap | HTMLVideoElement): string => {
    const width = 'videoWidth' in source ? source.videoWidth : source.width;
    const height = 'videoHeight' in source ? source.videoHeight : source.height;
    if (!width || !height) return '';
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext('2d');
    if (!context) return '';
    // jsQR ignores alpha and reads RGB directly, so transparent pixels would be
    // treated as black. Composite over white first so transparent-background QR
    // exports do not become black-on-black and fail to decode.
    context.fillStyle = '#ffffff';
    context.fillRect(0, 0, width, height);
    context.drawImage(source, 0, 0, width, height);
    const imageData = context.getImageData(0, 0, width, height);
    return String(jsQR(imageData.data, width, height)?.data || '').trim();
  };

  const decodeTotpQrImage = async (source: ImageBitmap): Promise<boolean> => {
    const detector = createTotpQrDetector();
    if (detector) {
      try {
        const results = await detector.detect(source);
        const value = String(results[0]?.rawValue || '').trim();
        if (value && applyTotpQrValue(value)) return true;
      } catch {
        // Fall back to jsQR when the native detector is present but not usable.
      }
    }
    const value = decodeTotpQrCanvas(source);
    return value ? applyTotpQrValue(value) : false;
  };

  const handleTotpQrFile = async (file: File | null) => {
    if (!file) return;
    if (file.type && !file.type.startsWith('image/')) {
      setTotpQrStatus(t('txt_totp_qr_invalid_image_type'));
      return;
    }
    if (file.size > TOTP_QR_IMAGE_MAX_BYTES) {
      setTotpQrStatus(t('txt_totp_qr_image_too_large'));
      return;
    }
    setTotpQrBusy(true);
    setTotpQrStatus(t('txt_totp_qr_scanning'));
    let bitmap: ImageBitmap | null = null;
    try {
      bitmap = await createImageBitmap(file);
      const found = await decodeTotpQrImage(bitmap);
      if (!found) setTotpQrStatus(t('txt_totp_qr_not_found'));
    } catch {
      setTotpQrStatus(t('txt_totp_qr_scan_failed'));
    } finally {
      bitmap?.close();
      setTotpQrBusy(false);
    }
  };

  useEffect(() => {
    if (!totpQrOpen) {
      stopTotpQrScanner();
      return;
    }
    let stopped = false;
    let lastCanvasScan = 0;
    const detector = createTotpQrDetector();
    if (!navigator.mediaDevices?.getUserMedia) {
      setTotpQrStatus(t('txt_totp_qr_camera_unavailable'));
      return () => {
        stopped = true;
        stopTotpQrScanner();
      };
    }

    const scan = async () => {
      if (stopped) return;
      const video = totpQrVideoRef.current;
      if (!video || video.readyState < HTMLMediaElement.HAVE_CURRENT_DATA) {
        totpQrFrameRef.current = window.requestAnimationFrame(scan);
        return;
      }
      try {
        let value = '';
        if (detector) {
          try {
            const results = await detector.detect(video);
            value = String(results[0]?.rawValue || '').trim();
          } catch {
            // Fall back to jsQR when the native detector is present but not usable.
          }
        }
        // The jsQR fallback runs a synchronous full-frame decode, so throttle
        // it to a few times per second instead of every animation frame to
        // avoid pegging the CPU while a code is being aligned.
        if (!value) {
          const now = performance.now();
          if (now - lastCanvasScan >= 250) {
            lastCanvasScan = now;
            value = decodeTotpQrCanvas(video);
          }
        }
        if (value && applyTotpQrValue(value)) return;
      } catch {
        // Keep the camera active; transient frame decode failures are common.
      }
      totpQrFrameRef.current = window.requestAnimationFrame(scan);
    };

    setTotpQrBusy(true);
    setTotpQrStatus(t('txt_totp_qr_starting_camera'));
    navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false })
      .then((stream) => {
        if (stopped) {
          for (const track of stream.getTracks()) track.stop();
          return;
        }
        totpQrStreamRef.current = stream;
        const video = totpQrVideoRef.current;
        if (!video) return;
        video.srcObject = stream;
        setTotpQrStatus(t('txt_totp_qr_point_camera'));
        void video.play().then(() => {
          setTotpQrBusy(false);
          totpQrFrameRef.current = window.requestAnimationFrame(scan);
        }).catch(() => {
          setTotpQrBusy(false);
          setTotpQrStatus(t('txt_totp_qr_camera_unavailable'));
        });
      })
      .catch(() => {
        setTotpQrBusy(false);
        setTotpQrStatus(t('txt_totp_qr_camera_unavailable'));
      });

    return () => {
      stopped = true;
      stopTotpQrScanner();
    };
  }, [totpQrOpen]);

  const formatDownloadLabel = (attachmentId: string) => {
    const downloadKey = `${props.selectedCipher?.id || ''}:${attachmentId}`;
    if (props.downloadingAttachmentKey !== downloadKey) return t('txt_download');
    return props.attachmentDownloadPercent == null
      ? t('txt_downloading')
      : t('txt_downloading_percent', { percent: props.attachmentDownloadPercent });
  };
  const uploadLabel =
    props.attachmentUploadPercent == null
      ? t('txt_uploading_attachment_named', { name: props.uploadingAttachmentName || t('txt_attachment') })
      : t('txt_uploading_attachment_named_percent', {
          name: props.uploadingAttachmentName || t('txt_attachment'),
          percent: props.attachmentUploadPercent,
        });

  const addLoginUri = () => {
    props.onUpdateDraft({ loginUris: [...props.draft.loginUris, createEmptyLoginUri()] });
  };

  const removeLoginUri = (index: number) => {
    props.onUpdateDraft({ loginUris: props.draft.loginUris.filter((_, itemIndex) => itemIndex !== index) });
  };

  const moveLoginUri = (fromIndex: number, toIndex: number) => {
    if (fromIndex < 0 || toIndex < 0 || fromIndex >= props.draft.loginUris.length || toIndex >= props.draft.loginUris.length || fromIndex === toIndex) return;
    props.onReorderDraftLoginUri(fromIndex, toIndex);
  };

  return (
    <>
      <div className="card">
        <div className="section-head">
          <h3 className="detail-title">{props.isCreating ? t('txt_new_type_header', { type: cipherTypeLabel(props.draft.type) }) : t('txt_edit_type_header', { type: cipherTypeLabel(props.draft.type) })}</h3>
          <button type="button" className={`btn btn-secondary small ${props.draft.favorite ? 'star-on' : ''}`} onClick={() => props.onUpdateDraft({ favorite: !props.draft.favorite })}>
            {props.draft.favorite ? <Star size={14} className="btn-icon" /> : <StarOff size={14} className="btn-icon" />}
            {t('txt_favorite')}
          </button>
        </div>
        <div className="field-grid">
          <label className="field">
            <span>{t('txt_type')}</span>
            <select
              className="input"
              value={props.draft.type}
              disabled={!props.isCreating}
              onInput={(e) => {
                const nextType = Number((e.currentTarget as HTMLSelectElement).value);
                props.onUpdateDraft({ type: nextType });
                if (nextType === 5) props.onSeedSshDefaults();
              }}
            >
              {createTypeOptions.map((option) => (
                <option key={option.type} value={option.type}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>{t('txt_folder')}</span>
            <select className="input" value={props.draft.folderId} onInput={(e) => props.onUpdateDraft({ folderId: (e.currentTarget as HTMLSelectElement).value })}>
              <option value="">{t('txt_no_folder')}</option>
              {props.folders.map((folder) => (
                <option key={folder.id} value={folder.id}>
                  {folder.decName || folder.name || folder.id}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label className="field">
          <span>{t('txt_name')}</span>
          <input className="input" value={props.draft.name} onInput={(e) => props.onUpdateDraft({ name: (e.currentTarget as HTMLInputElement).value })} />
        </label>
      </div>

      {props.draft.type === 1 && (
        <div className="card">
          <h4>{t('txt_login_credentials')}</h4>
          <div className="field-grid">
            <label className="field">
              <span>{t('txt_username')}</span>
              <input className="input" value={props.draft.loginUsername} onInput={(e) => props.onUpdateDraft({ loginUsername: (e.currentTarget as HTMLInputElement).value })} />
            </label>
            <label className="field">
              <span>{t('txt_password')}</span>
              <input className="input" value={props.draft.loginPassword} onInput={(e) => props.onUpdateDraft({ loginPassword: (e.currentTarget as HTMLInputElement).value })} />
            </label>
          </div>
          <label className="field">
            <span>{t('txt_totp_secret')}</span>
            <div className="input-action-wrap">
              <input className="input" value={props.draft.loginTotp} onInput={(e) => props.onUpdateDraft({ loginTotp: (e.currentTarget as HTMLInputElement).value })} />
              <button
                type="button"
                className="input-icon-btn"
                title={t('txt_scan_totp_qr')}
                aria-label={t('txt_scan_totp_qr')}
                disabled={props.busy}
                onClick={() => {
                  setTotpQrStatus('');
                  setTotpQrOpen(true);
                }}
              >
                <QrCode size={18} className="btn-icon" />
              </button>
            </div>
          </label>
          <div className="section-head">
            <h4>{t('txt_websites')}</h4>
            <button type="button" className="btn btn-secondary small" onClick={addLoginUri}>
              <Plus size={14} className="btn-icon" /> {t('txt_add_website')}
            </button>
          </div>
          {props.draft.loginUris.map((uriEntry, index) => (
            <WebsiteRow
              key={`uri-${index}`}
              uriEntry={uriEntry}
              index={index}
              canMoveUp={index > 0}
              canMoveDown={index < props.draft.loginUris.length - 1}
              canRemove={props.draft.loginUris.length > 1}
              onUpdateUri={props.onUpdateDraftLoginUri}
              onUpdateMatch={props.onUpdateDraftLoginUriMatch}
              onMove={moveLoginUri}
              onRemove={removeLoginUri}
            />
          ))}
          {props.draft.loginFido2Credentials.length > 0 && (
            <>
              <div className="section-head passkeys-section-head">
                <h4>{t('txt_passkeys')}</h4>
              </div>
              <div className="attachment-list">
                {props.draft.loginFido2Credentials.map((credential, index) => {
                  const createdAt = String(credential?.creationDate || '').trim();
                  const label = createdAt
                    ? t('txt_passkey_created_at_value', { value: formatHistoryTime(createdAt) })
                    : t('txt_passkey');
                  return (
                    <div key={`login-passkey-${index}`} className="attachment-row">
                      <div className="attachment-main">
                        <div className="attachment-text">
                          <strong>{t('txt_passkey')}</strong>
                          <span>{label}</span>
                        </div>
                      </div>
                      <div className="kv-actions">
                        <button
                          type="button"
                          className="btn btn-secondary small"
                          disabled={props.busy}
                          onClick={() => props.onRequestDeleteLoginPasskey(index)}
                        >
                          <X size={14} className="btn-icon" />
                          {t('txt_remove')}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      )}

      {props.draft.type === 3 && (
        <div className="card">
          <h4>{t('txt_card_details')}</h4>
          <div className="field-grid">
            <label className="field"><span>{t('txt_cardholder_name')}</span><input className="input" value={props.draft.cardholderName} onInput={(e) => props.onUpdateDraft({ cardholderName: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field">
              <span>{t('txt_number')}</span>
              <input
                className="input"
                value={props.draft.cardNumber}
                onInput={(e) => {
                  const value = (e.currentTarget as HTMLInputElement).value;
                  const detectedBrand = normalizeCardBrand(cardBrand(value) || '');
                  props.onUpdateDraft({
                    cardNumber: value,
                    ...(props.draft.cardBrand ? {} : { cardBrand: detectedBrand }),
                  });
                }}
              />
            </label>
            <label className="field">
              <span>{t('txt_brand')}</span>
              <div className="card-brand-select-row">
                <CardBrandIcon brand={normalizedDraftCardBrand} />
                <select
                  className="input card-brand-select"
                  value={normalizedDraftCardBrand}
                  onInput={(e) => props.onUpdateDraft({ cardBrand: (e.currentTarget as HTMLSelectElement).value })}
                >
                  <option value="">{t('txt_select')}</option>
                  {cardBrandOptions.map((brand) => (
                    <option key={brand} value={brand}>{brand}</option>
                  ))}
                </select>
              </div>
            </label>
            <label className="field"><span>{t('txt_security_code_cvv')}</span><input className="input" value={props.draft.cardCode} onInput={(e) => props.onUpdateDraft({ cardCode: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_expiry_month')}</span><input className="input" value={props.draft.cardExpMonth} onInput={(e) => props.onUpdateDraft({ cardExpMonth: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_expiry_year')}</span><input className="input" value={props.draft.cardExpYear} onInput={(e) => props.onUpdateDraft({ cardExpYear: (e.currentTarget as HTMLInputElement).value })} /></label>
          </div>
        </div>
      )}

      {props.draft.type === 4 && (
        <div className="card">
          <h4>{t('txt_identity_details')}</h4>
          <div className="field-grid">
            <label className="field"><span>{t('txt_title')}</span><input className="input" value={props.draft.identTitle} onInput={(e) => props.onUpdateDraft({ identTitle: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_first_name')}</span><input className="input" value={props.draft.identFirstName} onInput={(e) => props.onUpdateDraft({ identFirstName: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_middle_name')}</span><input className="input" value={props.draft.identMiddleName} onInput={(e) => props.onUpdateDraft({ identMiddleName: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_last_name')}</span><input className="input" value={props.draft.identLastName} onInput={(e) => props.onUpdateDraft({ identLastName: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_username')}</span><input className="input" value={props.draft.identUsername} onInput={(e) => props.onUpdateDraft({ identUsername: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_company')}</span><input className="input" value={props.draft.identCompany} onInput={(e) => props.onUpdateDraft({ identCompany: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_ssn')}</span><input className="input" value={props.draft.identSsn} onInput={(e) => props.onUpdateDraft({ identSsn: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_passport_number')}</span><input className="input" value={props.draft.identPassportNumber} onInput={(e) => props.onUpdateDraft({ identPassportNumber: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_license_number')}</span><input className="input" value={props.draft.identLicenseNumber} onInput={(e) => props.onUpdateDraft({ identLicenseNumber: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_email')}</span><input className="input" value={props.draft.identEmail} onInput={(e) => props.onUpdateDraft({ identEmail: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_phone')}</span><input className="input" value={props.draft.identPhone} onInput={(e) => props.onUpdateDraft({ identPhone: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_address_1')}</span><input className="input" value={props.draft.identAddress1} onInput={(e) => props.onUpdateDraft({ identAddress1: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_address_2')}</span><input className="input" value={props.draft.identAddress2} onInput={(e) => props.onUpdateDraft({ identAddress2: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_address_3')}</span><input className="input" value={props.draft.identAddress3} onInput={(e) => props.onUpdateDraft({ identAddress3: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_city_town')}</span><input className="input" value={props.draft.identCity} onInput={(e) => props.onUpdateDraft({ identCity: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_state_province')}</span><input className="input" value={props.draft.identState} onInput={(e) => props.onUpdateDraft({ identState: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_postal_code')}</span><input className="input" value={props.draft.identPostalCode} onInput={(e) => props.onUpdateDraft({ identPostalCode: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_country')}</span><input className="input" value={props.draft.identCountry} onInput={(e) => props.onUpdateDraft({ identCountry: (e.currentTarget as HTMLInputElement).value })} /></label>
          </div>
        </div>
      )}

      {props.draft.type === 5 && (
        <div className="card">
          <div className="section-head">
            <h4>{t('txt_ssh_key')}</h4>
            <button
              type="button"
              className="btn btn-secondary small"
              disabled={!props.isCreating}
              onClick={() => props.onSeedSshDefaults(true)}
            >
              <RefreshCw size={14} className="btn-icon" /> {t('txt_regenerate')}
            </button>
          </div>
          <label className="field">
            <span>{t('txt_private_key')}</span>
            <textarea
              className="input textarea"
              value={props.draft.sshPrivateKey}
              disabled={!props.isCreating}
              onInput={(e) => props.onUpdateDraft({ sshPrivateKey: (e.currentTarget as HTMLTextAreaElement).value })}
            />
          </label>
          <label className="field">
            <span>{t('txt_public_key')}</span>
            <textarea
              className="input textarea"
              value={props.draft.sshPublicKey}
              disabled={!props.isCreating}
              onInput={(e) => props.onUpdateSshPublicKey((e.currentTarget as HTMLTextAreaElement).value)}
            />
          </label>
          <label className="field">
            <span>{t('txt_fingerprint')}</span>
            <input className="input input-readonly" value={props.draft.sshFingerprint} readOnly />
          </label>
        </div>
      )}

      {props.draft.type === 6 && (
        <div className="card">
          <h4>{t('txt_bank_account_details')}</h4>
          <div className="field-grid">
            <label className="field"><span>{t('txt_bank_name')}</span><input className="input" value={props.draft.bankName} onInput={(e) => props.onUpdateDraft({ bankName: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_name_on_account')}</span><input className="input" value={props.draft.bankNameOnAccount} onInput={(e) => props.onUpdateDraft({ bankNameOnAccount: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_account_type')}</span><input className="input" value={props.draft.bankAccountType} onInput={(e) => props.onUpdateDraft({ bankAccountType: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_account_number')}</span><input className="input" value={props.draft.bankAccountNumber} onInput={(e) => props.onUpdateDraft({ bankAccountNumber: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_routing_number')}</span><input className="input" value={props.draft.bankRoutingNumber} onInput={(e) => props.onUpdateDraft({ bankRoutingNumber: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_branch_number')}</span><input className="input" value={props.draft.bankBranchNumber} onInput={(e) => props.onUpdateDraft({ bankBranchNumber: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_pin')}</span><input className="input" value={props.draft.bankPin} onInput={(e) => props.onUpdateDraft({ bankPin: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_swift_code')}</span><input className="input" value={props.draft.bankSwiftCode} onInput={(e) => props.onUpdateDraft({ bankSwiftCode: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_iban')}</span><input className="input" value={props.draft.bankIban} onInput={(e) => props.onUpdateDraft({ bankIban: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_bank_contact_phone')}</span><input className="input" value={props.draft.bankContactPhone} onInput={(e) => props.onUpdateDraft({ bankContactPhone: (e.currentTarget as HTMLInputElement).value })} /></label>
          </div>
        </div>
      )}

      {props.draft.type === 7 && (
        <div className="card">
          <h4>{t('txt_drivers_license_details')}</h4>
          <div className="field-grid">
            <label className="field"><span>{t('txt_first_name')}</span><input className="input" value={props.draft.licenseFirstName} onInput={(e) => props.onUpdateDraft({ licenseFirstName: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_middle_name')}</span><input className="input" value={props.draft.licenseMiddleName} onInput={(e) => props.onUpdateDraft({ licenseMiddleName: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_last_name')}</span><input className="input" value={props.draft.licenseLastName} onInput={(e) => props.onUpdateDraft({ licenseLastName: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_date_of_birth')}</span><input className="input" value={props.draft.licenseDateOfBirth} onInput={(e) => props.onUpdateDraft({ licenseDateOfBirth: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_license_number')}</span><input className="input" value={props.draft.licenseNumber} onInput={(e) => props.onUpdateDraft({ licenseNumber: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_issuing_country')}</span><input className="input" value={props.draft.licenseIssuingCountry} onInput={(e) => props.onUpdateDraft({ licenseIssuingCountry: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_issuing_state')}</span><input className="input" value={props.draft.licenseIssuingState} onInput={(e) => props.onUpdateDraft({ licenseIssuingState: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_issue_date')}</span><input className="input" value={props.draft.licenseIssueDate} onInput={(e) => props.onUpdateDraft({ licenseIssueDate: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_expiration_date')}</span><input className="input" value={props.draft.licenseExpirationDate} onInput={(e) => props.onUpdateDraft({ licenseExpirationDate: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_issuing_authority')}</span><input className="input" value={props.draft.licenseIssuingAuthority} onInput={(e) => props.onUpdateDraft({ licenseIssuingAuthority: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_license_class')}</span><input className="input" value={props.draft.licenseClass} onInput={(e) => props.onUpdateDraft({ licenseClass: (e.currentTarget as HTMLInputElement).value })} /></label>
          </div>
        </div>
      )}

      {props.draft.type === 8 && (
        <div className="card">
          <h4>{t('txt_passport_details')}</h4>
          <div className="field-grid">
            <label className="field"><span>{t('txt_surname')}</span><input className="input" value={props.draft.passportSurname} onInput={(e) => props.onUpdateDraft({ passportSurname: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_given_name')}</span><input className="input" value={props.draft.passportGivenName} onInput={(e) => props.onUpdateDraft({ passportGivenName: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_date_of_birth')}</span><input className="input" value={props.draft.passportDateOfBirth} onInput={(e) => props.onUpdateDraft({ passportDateOfBirth: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_sex')}</span><input className="input" value={props.draft.passportSex} onInput={(e) => props.onUpdateDraft({ passportSex: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_birth_place')}</span><input className="input" value={props.draft.passportBirthPlace} onInput={(e) => props.onUpdateDraft({ passportBirthPlace: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_nationality')}</span><input className="input" value={props.draft.passportNationality} onInput={(e) => props.onUpdateDraft({ passportNationality: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_issuing_country')}</span><input className="input" value={props.draft.passportIssuingCountry} onInput={(e) => props.onUpdateDraft({ passportIssuingCountry: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_passport_number')}</span><input className="input" value={props.draft.passportNumber} onInput={(e) => props.onUpdateDraft({ passportNumber: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_passport_type')}</span><input className="input" value={props.draft.passportType} onInput={(e) => props.onUpdateDraft({ passportType: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_national_id_number')}</span><input className="input" value={props.draft.passportNationalIdentificationNumber} onInput={(e) => props.onUpdateDraft({ passportNationalIdentificationNumber: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_issuing_authority')}</span><input className="input" value={props.draft.passportIssuingAuthority} onInput={(e) => props.onUpdateDraft({ passportIssuingAuthority: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_issue_date')}</span><input className="input" value={props.draft.passportIssueDate} onInput={(e) => props.onUpdateDraft({ passportIssueDate: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_expiration_date')}</span><input className="input" value={props.draft.passportExpirationDate} onInput={(e) => props.onUpdateDraft({ passportExpirationDate: (e.currentTarget as HTMLInputElement).value })} /></label>
          </div>
        </div>
      )}

      <div className="card">
        <div className="section-head attachment-head">
          <h4>{t('txt_attachments')}</h4>
          <button
            type="button"
            className="btn btn-secondary small attachment-add-btn"
            disabled={props.busy}
            onClick={() => props.attachmentInputRef.current?.click()}
            title={t('txt_upload_attachments')}
            aria-label={t('txt_upload_attachments')}
          >
            <Plus size={14} className="btn-icon" />
          </button>
        </div>
        {!!props.uploadingAttachmentName && <div className="detail-sub">{uploadLabel}</div>}
        {!props.isCreating && props.selectedCipher && props.editExistingAttachments.length > 0 && (
          <div className="attachment-list">
            {props.editExistingAttachments.map((attachment) => {
              const attachmentId = String(attachment?.id || '').trim();
              if (!attachmentId) return null;
              const removed = !!props.removedAttachmentIds[attachmentId];
              const fileName = String(attachment.decFileName || attachment.fileName || attachmentId).trim() || attachmentId;
              return (
                <div key={`edit-attachment-${attachmentId}`} className={`attachment-row ${removed ? 'is-removed' : ''}`}>
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
                      disabled={props.busy || removed || props.downloadingAttachmentKey === `${props.selectedCipher?.id || ''}:${attachmentId}`}
                      onClick={() => props.onDownloadAttachment(props.selectedCipher as Cipher, attachmentId)}
                    >
                      <Download size={14} className="btn-icon" /> {formatDownloadLabel(attachmentId)}
                    </button>
                    <button type="button" className="btn btn-secondary small" disabled={props.busy} onClick={() => props.onToggleExistingAttachmentRemoval(attachmentId)}>
                      <X size={14} className="btn-icon" />
                      {removed ? t('txt_cancel') : t('txt_remove')}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
        {!!props.removedAttachmentCount && <div className="detail-sub">{t('txt_marked_for_removal_count', { count: props.removedAttachmentCount })}</div>}
        <input
          ref={props.attachmentInputRef}
          type="file"
          className="attachment-file-input"
          multiple
          disabled={props.busy}
          onChange={(e) => {
            const input = e.currentTarget as HTMLInputElement;
            props.onQueueAttachmentFiles(input.files);
            input.value = '';
          }}
        />
        {!!props.attachmentQueue.length && (
          <div className="attachment-list">
            <div className="attachment-queue-title">{t('txt_new_attachments')}</div>
            {props.attachmentQueue.map((file, index) => (
              <div key={`queued-attachment-${index}-${file.name}`} className="attachment-row">
                <div className="attachment-main">
                  <Upload size={14} />
                  <div className="attachment-text">
                    <strong className="value-ellipsis" title={file.name}>{file.name}</strong>
                    <span>{formatAttachmentSize({ size: file.size })}</span>
                  </div>
                </div>
                <div className="kv-actions">
                  <button type="button" className="btn btn-secondary small" disabled={props.busy} onClick={() => props.onRemoveQueuedAttachment(index)}>
                    <X size={14} className="btn-icon" />
                    {t('txt_remove')}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <h4>{t('txt_additional_options')}</h4>
        <label className="field">
          <span>{t('txt_notes')}</span>
          <textarea className="input textarea" value={props.draft.notes} onInput={(e) => props.onUpdateDraft({ notes: (e.currentTarget as HTMLTextAreaElement).value })} />
        </label>
        <label className="check-line">
          <input type="checkbox" checked={props.draft.reprompt} onInput={(e) => props.onUpdateDraft({ reprompt: (e.currentTarget as HTMLInputElement).checked })} />
          {t('txt_master_password_reprompt')}
        </label>
        <div className="section-head">
          <h4>{t('txt_custom_fields')}</h4>
          <button type="button" className="btn btn-secondary small" onClick={props.onOpenFieldModal}>
            <Plus size={14} className="btn-icon" /> {t('txt_add_field')}
          </button>
        </div>
        {props.draft.customFields
          .map((field, originalIndex) => ({ field, originalIndex }))
          .filter((entry) => entry.field.type !== 3)
          .map(({ field, originalIndex }) => (
            <div key={`field-${originalIndex}`} className="custom-field-card">
              <label className="field custom-field-label">
                <span>{t('txt_field_label')}</span>
                <input className="input" value={field.label} onInput={(e) => props.onPatchDraftCustomField(originalIndex, { label: (e.currentTarget as HTMLInputElement).value })} />
              </label>
              <div className="custom-field-body">
                <div className="custom-field-value">
                  {field.type === 2 ? (
                    <label className="check-line cf-check custom-field-check">
                      <input
                        type="checkbox"
                        checked={toBooleanFieldValue(field.value)}
                        onInput={(e) => props.onPatchDraftCustomField(originalIndex, { value: (e.currentTarget as HTMLInputElement).checked ? 'true' : 'false' })}
                      />
                      <span>{toBooleanFieldValue(field.value) ? t('txt_checked') : t('txt_unchecked')}</span>
                    </label>
                  ) : (
                    <textarea
                      className="input textarea custom-field-textarea"
                      value={field.value}
                      onInput={(e) => props.onPatchDraftCustomField(originalIndex, { value: (e.currentTarget as HTMLTextAreaElement).value })}
                    />
                  )}
                </div>
                <button type="button" className="btn btn-secondary small custom-field-remove" onClick={() => props.onUpdateDraftCustomFields(props.draft.customFields.filter((_, i) => i !== originalIndex))}>
                  <X size={14} className="btn-icon" />
                  {t('txt_remove')}
                </button>
              </div>
            </div>
          ))}
      </div>

      <div className="detail-actions">
        <div className="actions">
          <button type="button" className="btn btn-primary" disabled={props.busy} onClick={props.onSave}>
            <CheckCheck size={14} className="btn-icon" />
            {t('txt_confirm')}
          </button>
          <button type="button" className="btn btn-secondary" disabled={props.busy} onClick={props.onCancel}>
            <X size={14} className="btn-icon" />
            {t('txt_cancel')}
          </button>
        </div>
        {!props.isCreating && props.selectedCipher && (
          <button type="button" className="btn btn-danger" disabled={props.busy} onClick={props.onDeleteSelected}>
            <Trash2 size={14} className="btn-icon" />
            {t('txt_delete')}
          </button>
        )}
      </div>
      {props.localError && <div className="local-error">{props.localError}</div>}
      {totpQrOpen && typeof document !== 'undefined' ? createPortal((
        <div className="dialog-mask totp-scan-mask open" onClick={(event) => event.target === event.currentTarget && setTotpQrOpen(false)}>
          <section className="dialog-card totp-scan-dialog open" role="dialog" aria-modal="true" aria-label={t('txt_scan_totp_qr')}>
            <div className="totp-scan-head">
              <h3 className="dialog-title">{t('txt_scan_totp_qr')}</h3>
              <button
                type="button"
                className="totp-scan-close"
                onClick={() => setTotpQrOpen(false)}
                title={t('txt_close')}
                aria-label={t('txt_close')}
              >
                <X size={20} className="btn-icon" />
              </button>
            </div>
            <div className="totp-scan-frame">
              <video ref={totpQrVideoRef} className="totp-scan-video" muted playsInline />
              <div className="totp-scan-corners" aria-hidden="true" />
            </div>
            <div className="totp-scan-footer">
              <div className="dialog-message totp-scan-status">{totpQrStatus || t('txt_totp_qr_point_camera')}</div>
              <div className="actions totp-scan-actions">
                <button type="button" className="btn btn-secondary dialog-btn" disabled={totpQrBusy} onClick={() => totpQrFileRef.current?.click()}>
                  <Upload size={14} className="btn-icon" />
                  {t('txt_totp_qr_choose_image')}
                </button>
                <button type="button" className="btn btn-primary dialog-btn" onClick={() => setTotpQrOpen(false)}>
                  <X size={14} className="btn-icon" />
                  {t('txt_close')}
                </button>
              </div>
            </div>
            <input
              ref={totpQrFileRef}
              type="file"
              accept="image/*"
              className="attachment-file-input"
              onChange={(event) => {
                const input = event.currentTarget as HTMLInputElement;
                void handleTotpQrFile(input.files?.[0] || null);
                input.value = '';
              }}
            />
          </section>
        </div>
      ), document.body) : null}
    </>
  );
}
