import { useEffect, useRef, useState } from 'preact/hooks';
import { Clipboard, Download, Eye, Lock } from 'lucide-preact';
import { accessPublicSend, accessPublicSendFile, decryptPublicSend, decryptPublicSendFileBytes } from '@/lib/api/send';
import { copyTextToClipboard } from '@/lib/clipboard';
import { toBufferSource } from '@/lib/crypto';
import { downloadBytesAsFile, readResponseBytesWithProgress } from '@/lib/download';
import NotFoundPage from '@/components/NotFoundPage';
import StandalonePageFrame from '@/components/StandalonePageFrame';
import { getDemoPublicSend, IS_DEMO_MODE } from '@/lib/demo';
import { t } from '@/lib/i18n';

interface PublicSendPageProps {
  accessId: string;
  keyPart: string | null;
}

interface PublicSendFileData {
  id: string;
  fileName?: string | null;
  sizeName?: string | null;
}

interface PublicSendData {
  id: string;
  type: 0 | 1;
  decName?: string | null;
  decText?: string | null;
  decFileName?: string | null;
  expirationDate?: string | null;
  file?: PublicSendFileData | null;
}

function decodeBase64Url(value: string): Uint8Array | null {
  try {
    const raw = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = raw + '='.repeat((4 - (raw.length % 4)) % 4);
    const decoded = atob(padded);
    const out = new Uint8Array(decoded.length);
    for (let i = 0; i < decoded.length; i += 1) out[i] = decoded.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function hasUsableSendKey(keyPart: string | null): boolean {
  if (!keyPart) return false;
  const bytes = decodeBase64Url(keyPart);
  return !!bytes && bytes.length >= 16;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' ? value as Record<string, unknown> : null;
}

function formatSendDate(value: string | null | undefined): string {
  if (!value) return '';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return '';
  return parsed.toLocaleString();
}

function optionalString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function parsePublicSendData(value: unknown): PublicSendData | null {
  const source = asRecord(value);
  if (!source) return null;
  const id = optionalString(source.id);
  const rawType = Number(source.type);
  if (!id || (rawType !== 0 && rawType !== 1)) return null;

  const fileSource = asRecord(source.file);
  const fileId = optionalString(fileSource?.id);
  const file = fileSource && fileId
    ? {
        id: fileId,
        fileName: optionalString(fileSource.fileName),
        sizeName: optionalString(fileSource.sizeName),
      }
    : null;
  if (rawType === 1 && !file) return null;

  return {
    id,
    type: rawType,
    decName: optionalString(source.decName),
    decText: optionalString(source.decText),
    decFileName: optionalString(source.decFileName),
    expirationDate: optionalString(source.expirationDate),
    file,
  };
}

export default function PublicSendPage(props: PublicSendPageProps) {
  const initialDemoSend = IS_DEMO_MODE ? getDemoPublicSend(props.accessId) : null;
  const [loading, setLoading] = useState(!IS_DEMO_MODE);
  const [password, setPassword] = useState('');
  const [needPassword, setNeedPassword] = useState(false);
  const [error, setError] = useState('');
  const [notFound, setNotFound] = useState(IS_DEMO_MODE && !initialDemoSend);
  const [sendData, setSendData] = useState<PublicSendData | null>(initialDemoSend);
  const [busy, setBusy] = useState(false);
  const [downloadPercent, setDownloadPercent] = useState<number | null>(null);
  const loadRequestRef = useRef(0);
  const loadAbortRef = useRef<AbortController | null>(null);

  async function loadSend(pass?: string): Promise<void> {
    loadAbortRef.current?.abort();
    const controller = new AbortController();
    const requestId = loadRequestRef.current + 1;
    loadRequestRef.current = requestId;
    loadAbortRef.current = controller;
    setBusy(true);
    setError('');
    setNotFound(false);
    setLoading(true);
    try {
      if (IS_DEMO_MODE) {
        const demoSend = getDemoPublicSend(props.accessId);
        if (!demoSend) {
          setNotFound(true);
          setSendData(null);
          return;
        }
        setSendData(demoSend);
        setNeedPassword(false);
        return;
      }
      if (!hasUsableSendKey(props.keyPart)) {
        setNotFound(true);
        setSendData(null);
        return;
      }
      const data = await accessPublicSend(props.accessId, props.keyPart, pass, { signal: controller.signal });
      if (controller.signal.aborted || requestId !== loadRequestRef.current) return;
      if (!props.keyPart) {
        setError(t('txt_this_link_is_missing_decryption_key'));
        setSendData(null);
        return;
      }
      const decrypted = await decryptPublicSend(data, props.keyPart);
      if (controller.signal.aborted || requestId !== loadRequestRef.current) return;
      const parsed = parsePublicSendData(decrypted);
      if (!parsed) throw new Error(t('txt_send_unavailable'));
      setSendData(parsed);
      setNeedPassword(false);
    } catch (e) {
      if (controller.signal.aborted || requestId !== loadRequestRef.current) return;
      const err = e as Error & { status?: number };
      if (err.status === 401) {
        setNeedPassword(true);
        setError(t('txt_this_send_is_password_protected'));
      } else if (err.status === 404) {
        setNeedPassword(false);
        setNotFound(true);
        setError('');
      } else {
        setError(err.message || t('txt_failed_to_open_send'));
      }
      setSendData(null);
    } finally {
      if (controller.signal.aborted || requestId !== loadRequestRef.current) return;
      setBusy(false);
      setLoading(false);
    }
  }

  async function downloadFile(): Promise<void> {
    if (!sendData?.id || !sendData?.file?.id) return;
    setBusy(true);
    setDownloadPercent(null);
    setError('');
    try {
      if (IS_DEMO_MODE) {
        const bytes = new TextEncoder().encode('NodeWarden demo file Send.\nThis download is generated locally in demo mode.\n');
        downloadBytesAsFile(bytes, sendData.decFileName || sendData.file?.fileName || 'nodewarden-demo-send.txt', 'application/octet-stream');
        return;
      }
      const url = await accessPublicSendFile(sendData.id, sendData.file.id, props.keyPart, password || undefined);
      const resp = await fetch(url);
      if (!resp.ok) throw new Error(t('txt_download_failed'));
      const encryptedBytes = await readResponseBytesWithProgress(resp, (progress) => setDownloadPercent(progress.percent));
      let blob: Blob;
      if (props.keyPart) {
        try {
          const decryptedBytes = await decryptPublicSendFileBytes(encryptedBytes, props.keyPart);
          blob = new Blob([toBufferSource(decryptedBytes)], { type: 'application/octet-stream' });
        } catch {
          // Legacy compatibility: early web-created file sends uploaded plaintext bytes.
          blob = new Blob([toBufferSource(encryptedBytes)], { type: 'application/octet-stream' });
        }
      } else {
        blob = new Blob([toBufferSource(encryptedBytes)], { type: 'application/octet-stream' });
      }
      downloadBytesAsFile(
        new Uint8Array(await blob.arrayBuffer()),
        sendData.decFileName || sendData.file?.fileName || t('txt_send_file'),
        'application/octet-stream'
      );
    } catch (e) {
      const err = e as Error;
      setError(err.message || t('txt_download_failed'));
    } finally {
      setBusy(false);
      setDownloadPercent(null);
    }
  }

  useEffect(() => {
    if (IS_DEMO_MODE) {
      const demoSend = getDemoPublicSend(props.accessId);
      setSendData(demoSend);
      setNotFound(!demoSend);
      setNeedPassword(false);
      setError('');
      setLoading(false);
      return;
    }
    void loadSend();
    return () => {
      loadAbortRef.current?.abort();
    };
  }, [props.accessId, props.keyPart]);

  if (!loading && notFound) {
    return <NotFoundPage title={t('txt_page_not_found')} message={t('txt_send_unavailable')} />;
  }

  return (
    <div className="auth-page public-send-page">
      <StandalonePageFrame
        title={sendData ? (sendData.decName || t('txt_no_name')) : t('txt_nodewarden_send')}
        eyebrow={sendData ? t('txt_nodewarden_send') : undefined}
      >
        {loading && <p className="muted">{t('txt_loading')}</p>}

        {!loading && needPassword && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void loadSend(password);
            }}
          >
            <label className="field">
              <span>{t('txt_password')}</span>
              <div className="password-wrap">
                <input
                  className="input"
                  type="password"
                  value={password}
                  autoComplete="current-password"
                  onInput={(e) => setPassword((e.currentTarget as HTMLInputElement).value)}
                />
              </div>
            </label>
            <button type="submit" className="btn btn-primary full" disabled={busy}>
              <Lock size={14} className="btn-icon" /> {t('txt_unlock_send')}
            </button>
          </form>
        )}

        {!loading && sendData && (
          <>
            {sendData.type === 0 ? (
              <div className="card public-send-card">
                <div className="public-send-card-head">
                  <span>{t('txt_text_send')}</span>
                  <button
                    type="button"
                    className="btn btn-secondary small public-send-copy-btn"
                    disabled={!sendData.decText}
                    onClick={() => void copyTextToClipboard(sendData.decText || '')}
                  >
                    <Clipboard size={14} className="btn-icon" />
                    {t('txt_copy')}
                  </button>
                </div>
                <div className="notes">{sendData.decText || ''}</div>
              </div>
            ) : (
              <div className="card public-send-card">
                <div className="kv-line">
                  <span>{t('txt_file')}</span>
                  <strong>{sendData.decFileName || sendData.file?.fileName || sendData.file?.sizeName || t('txt_encrypted_file')}</strong>
                </div>
                <button type="button" className="btn btn-primary full" disabled={busy} onClick={() => void downloadFile()}>
                  <Download size={14} className="btn-icon" /> {downloadPercent == null ? (busy ? t('txt_downloading') : t('txt_download')) : t('txt_downloading_percent', { percent: downloadPercent })}
                </button>
              </div>
            )}
            {!!sendData.expirationDate && <p className="muted">{t('txt_expires_at_value', { value: formatSendDate(sendData.expirationDate) })}</p>}
          </>
        )}

        {!loading && !sendData && !needPassword && !error && (
          <p className="muted">
            <Eye size={14} className="inline-status-icon" /> {t('txt_send_unavailable')}
          </p>
        )}
        {!!error && <p className="local-error">{error}</p>}
      </StandalonePageFrame>
    </div>
  );
}
