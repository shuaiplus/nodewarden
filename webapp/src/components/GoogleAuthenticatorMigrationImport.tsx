import { useEffect, useRef, useState } from 'preact/hooks';
import { FileUp, QrCode, Upload, X } from 'lucide-preact';
import type { CiphersImportPayload } from '@/lib/api/vault';
import type { ImportResultSummary } from '@/components/ImportPage';
import { parseGoogleAuthenticatorMigrationPage } from '@/lib/google-authenticator-migration';
import {
  GoogleAuthenticatorMigrationSession,
  type MigrationReviewItem,
  type MigrationSessionError,
} from '@/lib/google-authenticator-migration-session';
import { t } from '@/lib/i18n';
import {
  assertQrImageFile,
  createQrCodeDetector,
  decodeQrFromCanvas,
  decodeSingleQrCode,
} from '@/lib/qr-code';

interface GoogleAuthenticatorMigrationImportProps {
  folderMode: 'original' | 'none' | 'target';
  targetFolderId: string | null;
  disabled?: boolean;
  onImport: (
    payload: CiphersImportPayload,
    options: { folderMode: 'original' | 'none' | 'target'; targetFolderId: string | null },
  ) => Promise<ImportResultSummary>;
  onNotify: (type: 'success' | 'error', text: string) => void;
  onSummary: (summary: ImportResultSummary) => void;
}

function excludedReasonLabel(reason: string): string {
  if (reason === 'hotp') return t('txt_ga_migration_exclude_hotp');
  if (reason === 'unsupported-algorithm') return t('txt_ga_migration_exclude_algorithm');
  if (reason === 'unsupported-digits') return t('txt_ga_migration_exclude_digits');
  if (reason === 'unsupported-type') return t('txt_ga_migration_exclude_type');
  if (reason === 'missing-secret') return t('txt_ga_migration_exclude_secret');
  return t('txt_ga_migration_exclude_malformed');
}

function sessionErrorLabel(reason: MigrationSessionError): string {
  if (reason === 'batch-conflict') return t('txt_ga_migration_batch_conflict');
  if (reason === 'conflicting-page') return t('txt_ga_migration_conflicting_page');
  if (reason === 'empty-selection') return t('txt_ga_migration_empty_selection');
  if (reason === 'incomplete-batch') return t('txt_ga_migration_incomplete');
  if (reason === 'over-limit') return t('txt_ga_migration_over_limit');
  return t('txt_ga_migration_invalid_page');
}

function reviewLabel(item: MigrationReviewItem): string {
  if (item.kind === 'excluded') return excludedReasonLabel(item.reason);
  const issuer = item.issuer.trim();
  const name = item.name.trim();
  if (issuer && name) return `${issuer}: ${name}`;
  return issuer || name || t('txt_ga_migration_unnamed');
}

export default function GoogleAuthenticatorMigrationImport(props: GoogleAuthenticatorMigrationImportProps) {
  const sessionRef = useRef(new GoogleAuthenticatorMigrationSession());
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const frameRef = useRef<number | null>(null);
  const fileRef = useRef<HTMLInputElement | null>(null);
  const generationRef = useRef(0);
  const lastRawRef = useRef('');
  const [cameraOpen, setCameraOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [status, setStatus] = useState(t('txt_ga_migration_scan_page'));
  const [snapshot, setSnapshot] = useState(() => sessionRef.current.snapshot());

  const refresh = () => setSnapshot(sessionRef.current.snapshot());

  const stopCamera = () => {
    if (frameRef.current != null) {
      window.cancelAnimationFrame(frameRef.current);
      frameRef.current = null;
    }
    if (streamRef.current) {
      for (const track of streamRef.current.getTracks()) track.stop();
      streamRef.current = null;
    }
    if (videoRef.current) videoRef.current.srcObject = null;
  };

  const clearSession = (message?: string) => {
    generationRef.current += 1;
    stopCamera();
    setCameraOpen(false);
    sessionRef.current.clear();
    lastRawRef.current = '';
    setBusy(false);
    setSubmitting(false);
    setStatus(message || t('txt_ga_migration_scan_page'));
    refresh();
  };

  const ingestRaw = (raw: string): boolean => {
    const value = String(raw || '').trim();
    if (!value) {
      setStatus(t('txt_totp_qr_not_found'));
      return false;
    }
    if (value === lastRawRef.current) {
      setStatus(t('txt_ga_migration_duplicate_page'));
      return true;
    }

    const parsed = parseGoogleAuthenticatorMigrationPage(value);
    if (!parsed.ok) {
      setStatus(t('txt_ga_migration_invalid_page'));
      return false;
    }

    const result = sessionRef.current.addPage(parsed.page);
    refresh();
    if (!result.ok) {
      setStatus(sessionErrorLabel(result.reason));
      return false;
    }

    lastRawRef.current = value;
    if (result.duplicate) {
      setStatus(t('txt_ga_migration_duplicate_page'));
      return true;
    }

    const next = sessionRef.current.snapshot();
    if (next.status.phase === 'ready') {
      setStatus(t('txt_ga_migration_ready'));
      stopCamera();
      setCameraOpen(false);
    } else {
      setStatus(t('txt_ga_migration_progress', {
        received: String(next.receivedIndexes.length),
        total: String(next.batchSize || 0),
      }));
    }
    return true;
  };

  const handleImageFile = async (file: File | null) => {
    if (!file || submitting) return;
    const check = assertQrImageFile(file);
    if (check === 'invalid-type') {
      setStatus(t('txt_totp_qr_invalid_image_type'));
      return;
    }
    if (check === 'too-large') {
      setStatus(t('txt_totp_qr_image_too_large'));
      return;
    }

    const generation = generationRef.current;
    setBusy(true);
    setStatus(t('txt_totp_qr_scanning'));
    let bitmap: ImageBitmap | null = null;
    try {
      bitmap = await createImageBitmap(file);
      if (generation !== generationRef.current) return;
      const decoded = await decodeSingleQrCode(bitmap);
      if (generation !== generationRef.current) return;
      if (!decoded.ok) {
        setStatus(decoded.reason === 'multiple'
          ? t('txt_ga_migration_multiple_qr')
          : t('txt_totp_qr_not_found'));
        return;
      }
      ingestRaw(decoded.value);
    } catch {
      if (generation === generationRef.current) setStatus(t('txt_totp_qr_scan_failed'));
    } finally {
      bitmap?.close();
      if (generation === generationRef.current) setBusy(false);
    }
  };

  useEffect(() => {
    if (!cameraOpen) {
      stopCamera();
      return;
    }

    let stopped = false;
    let lastCanvasScan = 0;
    const detector = createQrCodeDetector();
    const generation = generationRef.current;

    if (!navigator.mediaDevices?.getUserMedia) {
      setStatus(t('txt_totp_qr_camera_unavailable'));
      setCameraOpen(false);
      return;
    }

    const scan = async () => {
      if (stopped || generation !== generationRef.current) return;
      const video = videoRef.current;
      if (!video || video.readyState < HTMLMediaElement.HAVE_CURRENT_DATA) {
        frameRef.current = window.requestAnimationFrame(scan);
        return;
      }
      try {
        let value = '';
        if (detector) {
          try {
            const results = await detector.detect(video);
            if (results.length > 1) {
              setStatus(t('txt_ga_migration_multiple_qr'));
            } else {
              value = String(results[0]?.rawValue || '').trim();
            }
          } catch {
            // Fall back to jsQR when the native detector is present but not usable.
          }
        }
        if (!value) {
          const now = performance.now();
          if (now - lastCanvasScan >= 250) {
            lastCanvasScan = now;
            value = decodeQrFromCanvas(video);
          }
        }
        if (value && ingestRaw(value) && sessionRef.current.snapshot().status.phase === 'ready') {
          return;
        }
      } catch {
        // Keep scanning through transient decode failures.
      }
      frameRef.current = window.requestAnimationFrame(scan);
    };

    setBusy(true);
    setStatus(t('txt_totp_qr_starting_camera'));
    navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false })
      .then((stream) => {
        if (stopped || generation !== generationRef.current) {
          for (const track of stream.getTracks()) track.stop();
          return;
        }
        streamRef.current = stream;
        const video = videoRef.current;
        if (!video) return;
        video.srcObject = stream;
        setStatus(t('txt_ga_migration_point_camera'));
        void video.play().then(() => {
          if (stopped || generation !== generationRef.current) return;
          setBusy(false);
          frameRef.current = window.requestAnimationFrame(scan);
        }).catch(() => {
          setBusy(false);
          setStatus(t('txt_totp_qr_camera_unavailable'));
          setCameraOpen(false);
        });
      })
      .catch(() => {
        setBusy(false);
        setStatus(t('txt_totp_qr_camera_unavailable'));
        setCameraOpen(false);
      });

    return () => {
      stopped = true;
      stopCamera();
    };
  }, [cameraOpen]);

  useEffect(() => () => {
    generationRef.current += 1;
    stopCamera();
    sessionRef.current.clear();
  }, []);

  const handleImport = async () => {
    if (submitting || busy) return;
    const built = sessionRef.current.buildImportPayload();
    if (!built.ok) {
      setStatus(sessionErrorLabel(built.reason));
      return;
    }

    setSubmitting(true);
    try {
      const summary = await props.onImport(built.payload, {
        folderMode: props.folderMode === 'original' ? 'none' : props.folderMode,
        targetFolderId: props.folderMode === 'target' ? props.targetFolderId : null,
      });
      const confirmed = summary.confirmedItemCount ?? summary.totalItems;
      sessionRef.current.clearSecrets();
      sessionRef.current.clear();
      lastRawRef.current = '';
      refresh();
      if (confirmed < summary.totalItems) {
        props.onNotify('error', t('txt_ga_migration_unknown_outcome'));
        setStatus(t('txt_ga_migration_unknown_outcome'));
        return;
      }
      props.onSummary(summary);
      props.onNotify('success', t('txt_ga_migration_success', { count: String(summary.totalItems) }));
      setStatus(t('txt_ga_migration_scan_page'));
    } catch (error) {
      const dispatched = !!(error as Error & { importDispatched?: boolean })?.importDispatched;
      if (dispatched) {
        sessionRef.current.clearSecrets();
        sessionRef.current.clear();
        lastRawRef.current = '';
        refresh();
        props.onNotify('error', t('txt_ga_migration_unknown_outcome'));
        setStatus(t('txt_ga_migration_unknown_outcome'));
      } else {
        const message = error instanceof Error ? error.message : t('txt_import_failed');
        props.onNotify('error', message);
        setStatus(message);
      }
    } finally {
      setSubmitting(false);
    }
  };

  const ready = snapshot.status.phase === 'ready';
  const blocked = snapshot.status.phase === 'blocked';
  const accepted = snapshot.reviewItems.filter((item) => item.kind === 'accepted');
  const excluded = snapshot.reviewItems.filter((item) => item.kind === 'excluded');

  return (
    <div className="ga-migration-import">
      <p className="backup-inline-note">{t('txt_ga_migration_hint')}</p>
      <div className="backup-inline-note">{status}</div>

      {snapshot.batchSize != null && (
        <div className="backup-inline-note">
          {t('txt_ga_migration_progress', {
            received: String(snapshot.receivedIndexes.length),
            total: String(snapshot.batchSize),
          })}
          {snapshot.missingIndexes.length > 0 && (
            <>
              {' '}
              {t('txt_ga_migration_missing_pages', {
                pages: snapshot.missingIndexes.map((index) => String(index + 1)).join(', '),
              })}
            </>
          )}
        </div>
      )}

      {cameraOpen && (
        <div className="totp-scan-frame ga-migration-camera">
          <video ref={videoRef} className="totp-scan-video" muted playsInline />
        </div>
      )}

      <div className="actions">
        <button
          type="button"
          className="btn btn-secondary"
          disabled={props.disabled || busy || submitting || ready || blocked}
          onClick={() => setCameraOpen(true)}
        >
          <QrCode size={15} /> {t('txt_scan_totp_qr')}
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={props.disabled || busy || submitting || ready || blocked}
          onClick={() => fileRef.current?.click()}
        >
          <Upload size={15} /> {t('txt_totp_qr_choose_image')}
        </button>
        {cameraOpen && (
          <button type="button" className="btn btn-secondary" onClick={() => setCameraOpen(false)}>
            <X size={15} /> {t('txt_close')}
          </button>
        )}
        <button type="button" className="btn btn-secondary" disabled={submitting} onClick={() => clearSession()}>
          {t('txt_ga_migration_clear')}
        </button>
      </div>

      <input
        ref={fileRef}
        type="file"
        accept="image/*"
        className="attachment-file-input"
        onChange={(event) => {
          const input = event.currentTarget as HTMLInputElement;
          void handleImageFile(input.files?.[0] || null);
          input.value = '';
        }}
      />

      {ready && (
        <div className="ga-migration-review">
          <h4>{t('txt_ga_migration_review_title')}</h4>
          <div className="field-grid">
            {accepted.map((item) => (
              <label key={item.id} className="field field-span-2">
                <span className="ga-migration-review-row">
                  <input
                    type="checkbox"
                    checked={item.selected}
                    disabled={submitting}
                    onChange={(event) => {
                      sessionRef.current.setSelected(item.id, (event.currentTarget as HTMLInputElement).checked);
                      refresh();
                    }}
                  />
                  <span>
                    {reviewLabel(item)}
                    <br />
                    <small>
                      {t('txt_ga_migration_page_label', { index: String(item.pageIndex + 1) })}
                      {' · '}
                      {t('txt_ga_migration_config', {
                        algorithm: item.algorithm,
                        digits: String(item.digits),
                      })}
                    </small>
                  </span>
                </span>
              </label>
            ))}
          </div>

          {excluded.length > 0 && (
            <>
              <h4>{t('txt_ga_migration_excluded_title')}</h4>
              <ul className="backup-inline-note">
                {excluded.map((item) => (
                  <li key={item.id}>
                    {t('txt_ga_migration_page_label', { index: String(item.pageIndex + 1) })}
                    {': '}
                    {excludedReasonLabel(item.reason)}
                  </li>
                ))}
              </ul>
            </>
          )}

          <div className="actions">
            <button
              type="button"
              className="btn btn-primary"
              disabled={props.disabled || submitting || snapshot.selectedCount === 0}
              onClick={() => void handleImport()}
            >
              <FileUp size={15} />
              {submitting ? t('txt_loading') : t('txt_ga_migration_import_selected')}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
