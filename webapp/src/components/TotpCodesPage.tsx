import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { Clipboard, Globe } from 'lucide-preact';
import { copyTextToClipboard as copyTextWithFeedback } from '@/lib/clipboard';
import { calcTotpNow, type TotpCodeResult } from '@/lib/crypto';
import { t } from '@/lib/i18n';
import type { Cipher } from '@/lib/types';
import LoadingState from '@/components/LoadingState';
import WebsiteIcon from '@/components/vault/WebsiteIcon';
import { formatTotp, isCipherVisibleInNormalVault } from '@/components/vault/vault-page-helpers';

interface TotpCodesPageProps {
  ciphers: Cipher[];
  loading: boolean;
  onNotify: (type: 'success' | 'error', text: string) => void;
}

const TOTP_RING_RADIUS = 14;
const TOTP_RING_CIRCUMFERENCE = 2 * Math.PI * TOTP_RING_RADIUS;
const TOTP_REFRESH_BATCH_SIZE = 16;

function TotpListIcon({ cipher }: { cipher: Cipher }) {
  return <WebsiteIcon cipher={cipher} fallback={<Globe size={18} />} />;
}

interface TotpRowProps {
  cipher: Cipher;
  live: TotpCodeResult | null;
  onCopy: (value: string) => void;
}

function TotpRow(props: TotpRowProps) {
  const name = props.cipher.decName || props.cipher.name || t('txt_no_name');
  const username = props.cipher.login?.decUsername || '';
  const period = Math.max(1, props.live?.period || 30);
  const progress = props.live ? Math.max(0, Math.min(period, props.live.remain)) / period : 0;

  return (
    <div className="totp-code-row">
      <div className="totp-code-info">
        <div className="list-icon-wrap">
          <TotpListIcon cipher={props.cipher} />
        </div>
        <div className="totp-code-meta">
          <div className="totp-code-name" title={name}>{name}</div>
          <div className="totp-code-username" title={username}>{username || t('txt_no_username')}</div>
        </div>
      </div>
      <div className="totp-code-main">
        <strong>{props.live ? formatTotp(props.live.code) : t('txt_text_3')}</strong>
        <div
          className="totp-timer"
          title={t('txt_refresh_in_seconds_s', { seconds: props.live ? props.live.remain : 0 })}
          aria-label={t('txt_refresh_in_seconds_s', { seconds: props.live ? props.live.remain : 0 })}
        >
          <svg viewBox="0 0 36 36" className="totp-ring" role="presentation" aria-hidden="true">
            <circle className="totp-ring-track" cx="18" cy="18" r={TOTP_RING_RADIUS} />
            <circle
              className="totp-ring-progress"
              cx="18"
              cy="18"
              r={TOTP_RING_RADIUS}
              style={{
                strokeDasharray: `${TOTP_RING_CIRCUMFERENCE} ${TOTP_RING_CIRCUMFERENCE}`,
                strokeDashoffset: String(
                  TOTP_RING_CIRCUMFERENCE -
                    TOTP_RING_CIRCUMFERENCE * progress
                ),
              }}
            />
          </svg>
          <span className="totp-timer-value">{props.live ? props.live.remain : 0}</span>
        </div>
        <button type="button" className="btn btn-secondary small totp-copy-btn" onClick={() => props.onCopy(props.live?.code || '')} aria-label={t('txt_copy')}>
          <Clipboard size={14} className="btn-icon" />
        </button>
      </div>
    </div>
  );
}

export default function TotpCodesPage(props: TotpCodesPageProps) {
  const [totpCodes, setTotpCodes] = useState<Record<string, TotpCodeResult | null>>({});
  const [columnCount, setColumnCount] = useState(1);
  const listRef = useRef<HTMLDivElement | null>(null);

  async function copyToClipboard(value: string): Promise<void> {
    await copyTextWithFeedback(value, { successMessage: t('txt_code_copied') });
  }

  const nameCollator = useMemo(
    () => new Intl.Collator(undefined, { sensitivity: 'base', numeric: true }),
    []
  );

  const totpItems = useMemo(
    () =>
      props.ciphers
        .filter((cipher) => isCipherVisibleInNormalVault(cipher) && !!cipher.login?.decTotp)
        .sort((a, b) => {
          const nameA = (a.decName || a.name || '').trim();
          const nameB = (b.decName || b.name || '').trim();
          return nameCollator.compare(nameA, nameB);
        }),
    [props.ciphers, nameCollator]
  );

  useEffect(() => {
    if (!totpItems.length) {
      setTotpCodes({});
      return;
    }
    let stopped = false;
    let activeRun = 0;
    let timer = 0;

    const refreshCodes = async () => {
      const runId = ++activeRun;
      const nextCodes: Record<string, TotpCodeResult | null> = {};
      for (let start = 0; start < totpItems.length; start += TOTP_REFRESH_BATCH_SIZE) {
        if (stopped || runId !== activeRun) return;
        const batch = totpItems.slice(start, start + TOTP_REFRESH_BATCH_SIZE);
        const entries = await Promise.all(
          batch.map(async (cipher) => {
            try {
              const next = await calcTotpNow(cipher.login?.decTotp || '');
              return [cipher.id, next] as const;
            } catch {
              return [cipher.id, null] as const;
            }
          })
        );
        for (const [id, code] of entries) nextCodes[id] = code;
        if (start + TOTP_REFRESH_BATCH_SIZE < totpItems.length) {
          await new Promise<void>((resolve) => window.setTimeout(resolve, 0));
        }
      }
      if (stopped || runId !== activeRun) return;
      setTotpCodes((prev) => {
        let changed = false;
        const next: Record<string, TotpCodeResult | null> = { ...prev };
        for (const id of Object.keys(next)) {
          if (id in nextCodes) continue;
          delete next[id];
          changed = true;
        }
        for (const [id, live] of Object.entries(nextCodes)) {
          const prevLive = next[id];
          if (
            prevLive?.code === live?.code &&
            prevLive?.remain === live?.remain &&
            prevLive?.period === live?.period
          ) continue;
          next[id] = live;
          changed = true;
        }
        return changed ? next : prev;
      });
    };

    const tick = () => {
      void refreshCodes();
    };

    tick();
    timer = window.setInterval(tick, 1000);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [totpItems]);

  useEffect(() => {
    const element = listRef.current;
    if (!element) return;

    const gap = 10;
    const minCardWidth = 320;
    const maxColumns = 4;

    const updateColumns = () => {
      const width = element.clientWidth;
      if (!width) return;
      const next = Math.max(1, Math.min(maxColumns, Math.floor((width + gap) / (minCardWidth + gap))));
      setColumnCount(next);
    };

    updateColumns();
    const observer = new ResizeObserver(() => updateColumns());
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  return (
    <div className="totp-codes-page">
      <div className="card">
        <div className="section-head">
          <h3 className="detail-title">{t('txt_verification_code')}</h3>
        </div>
        <div
          ref={listRef}
          className="totp-codes-list"
          style={{ '--totp-columns': String(columnCount) } as Record<string, string>}
        >
          {!totpItems.length && props.loading && <LoadingState lines={6} />}
          {!totpItems.length && !props.loading && <div className="empty">{t('txt_no_verification_codes')}</div>}
          {totpItems.map((cipher) => (
            <TotpRow
              key={cipher.id}
              cipher={cipher}
              live={totpCodes[cipher.id] || null}
              onCopy={(value) => void copyToClipboard(value)}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
