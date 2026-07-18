import { useEffect, useMemo, useState } from 'preact/hooks';
import { AlertTriangle, CheckCircle2, ExternalLink, Eye, EyeOff, RefreshCw, ScanSearch, ShieldAlert, ShieldCheck, Unplug } from 'lucide-preact';
import { Link } from 'wouter';
import { maskSecret } from '@/components/vault/vault-page-helpers';
import { getPasswordSecurityState, readPasswordSecurityState, startPasswordSecurityScan, subscribePasswordSecurityState } from '@/lib/password-security-cache';
import { t } from '@/lib/i18n';
import type { Cipher } from '@/lib/types';

interface PasswordSecurityPageProps {
  ciphers: Cipher[];
  loading: boolean;
}

type PasswordSecurityFilter = 'exposed' | 'reused' | 'weak' | 'all';

function vaultFingerprint(ciphers: Cipher[]): string {
  return JSON.stringify(ciphers.map((cipher) => ({
    id: cipher.id,
    type: cipher.type,
    revisionDate: cipher.revisionDate || '',
    deletedDate: cipher.deletedDate || (cipher as { deletedAt?: string | null }).deletedAt || '',
  })));
}

function formatCheckedAt(value: number): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(value);
}

export default function PasswordSecurityPage(props: PasswordSecurityPageProps) {
  const fingerprint = vaultFingerprint(props.ciphers);
  const [securityState, setSecurityState] = useState(() => getPasswordSecurityState(fingerprint));
  const [filter, setFilter] = useState<PasswordSecurityFilter>('all');
  const [revealedPasswordIds, setRevealedPasswordIds] = useState<Set<string>>(() => new Set());
  useEffect(() => {
    setSecurityState(getPasswordSecurityState(fingerprint));
    setFilter('all');
    setRevealedPasswordIds(new Set());
    return subscribePasswordSecurityState(() => {
      const next = readPasswordSecurityState(fingerprint);
      if (next) setSecurityState(next);
    });
  }, [fingerprint]);

  const { report, scannedAt, scanning, progress, scanError } = securityState;

  const eligibleCount = useMemo(
    () => props.ciphers.filter((cipher) => Number(cipher.type) === 1 && !cipher.deletedDate && !(cipher as { deletedAt?: string | null }).deletedAt && !!cipher.login?.decPassword).length,
    [props.ciphers],
  );
  const ciphersById = useMemo(() => new Map(props.ciphers.map((cipher) => [cipher.id, cipher])), [props.ciphers]);
  const filteredItems = useMemo(() => {
    if (!report || filter === 'all') return report?.items || [];
    if (filter === 'exposed') return report.items.filter((item) => (item.exposedCount || 0) > 0);
    if (filter === 'reused') return report.items.filter((item) => item.reusedCount > 1);
    return report.items.filter((item) => item.weak);
  }, [filter, report]);
  const allPasswordsVisible = !!report?.items.length && report.items.every((item) => revealedPasswordIds.has(item.cipherId));

  const togglePasswordVisibility = (cipherId: string) => {
    setRevealedPasswordIds((current) => {
      const next = new Set(current);
      if (next.has(cipherId)) next.delete(cipherId);
      else next.add(cipherId);
      return next;
    });
  };

  const toggleAllPasswordVisibility = () => {
    if (!report) return;
    setRevealedPasswordIds(allPasswordsVisible ? new Set() : new Set(report.items.map((item) => item.cipherId)));
  };

  const scan = () => {
    setRevealedPasswordIds(new Set());
    setFilter('all');
    startPasswordSecurityScan(fingerprint, props.ciphers);
  };

  return (
    <section className="password-security-page" aria-label={t('txt_password_security')}>
      <div className="password-security-intro card">
        <div className="password-security-intro-icon"><ShieldCheck size={22} /></div>
        <div>
          <h2>{t('txt_password_security')}</h2>
          <p>{t('txt_password_security_privacy')}</p>
          {scannedAt && <p className="password-security-checked-at">{t('txt_password_security_last_checked', { value: formatCheckedAt(scannedAt) })}</p>}
        </div>
        <div className="password-security-intro-actions">
          {report && <button type="button" className="btn btn-secondary password-security-toggle-all" onClick={toggleAllPasswordVisibility}>
            {allPasswordsVisible ? <EyeOff size={16} className="btn-icon" /> : <Eye size={16} className="btn-icon" />}
            {allPasswordsVisible ? t('txt_password_security_hide_all') : t('txt_password_security_show_all')}
          </button>}
          <button type="button" className="btn btn-primary password-security-scan" disabled={props.loading || scanning || eligibleCount === 0} onClick={scan}>
            {scanning ? <RefreshCw size={16} className="btn-icon spin" /> : <ScanSearch size={16} className="btn-icon" />}
            {scanning ? t('txt_checking_password_security') : report ? t('txt_recheck_password_security') : t('txt_check_password_security')}
          </button>
        </div>
      </div>

      {!report && !scanning && !props.loading && (
        <div className="password-security-empty card">
          <ShieldCheck size={26} aria-hidden="true" />
          <strong>{eligibleCount ? t('txt_password_security_ready') : t('txt_password_security_no_login')}</strong>
          <span>{eligibleCount ? t('txt_password_security_manual') : t('txt_password_security_no_login_help')}</span>
        </div>
      )}

      {(scanning || report) && (
        <div className="password-security-summary" aria-live="polite">
          <SecurityMetric icon={<ShieldAlert size={18} />} tone="danger" label={t('txt_exposed_passwords')} value={report?.exposedCount ?? 0} active={filter === 'exposed'} disabled={!report} onClick={() => setFilter('exposed')} />
          <SecurityMetric icon={<AlertTriangle size={18} />} tone="warning" label={t('txt_reused_passwords')} value={report?.reusedCount ?? 0} active={filter === 'reused'} disabled={!report} onClick={() => setFilter('reused')} />
          <SecurityMetric icon={<AlertTriangle size={18} />} tone="warning" label={t('txt_weak_passwords')} value={report?.weakCount ?? 0} active={filter === 'weak'} disabled={!report} onClick={() => setFilter('weak')} />
          <SecurityMetric icon={<CheckCircle2 size={18} />} tone="primary" label={t('txt_passwords_checked')} value={`${scanning ? progress.checked : report?.checkedCount || 0} / ${scanning ? progress.total : report?.eligibleCount || 0}`} active={filter === 'all'} disabled={!report} onClick={() => setFilter('all')} />
        </div>
      )}

      {scanError && <div className="password-security-notice warning card" role="alert"><Unplug size={16} />{t('txt_password_security_check_failed')}</div>}

      {report && (
        <section className="password-security-results card">
          {report.unavailableCount > 0 && (
            <div className="password-security-notice warning"><Unplug size={16} />{t('txt_password_security_unavailable', { count: report.unavailableCount })}</div>
          )}
          {!report.items.length ? (
            <div className="password-security-empty compact"><CheckCircle2 size={25} /><strong>{t('txt_no_password_risks')}</strong></div>
          ) : !filteredItems.length ? (
            <div className="password-security-empty compact"><CheckCircle2 size={25} /><strong>{t('txt_no_password_risks_in_filter')}</strong></div>
          ) : (
            <div className="password-security-list">
              {filteredItems.map((item) => {
                const cipher = ciphersById.get(item.cipherId);
                const name = String(cipher?.decName || cipher?.name || '');
                const password = String(cipher?.login?.decPassword || '');
                const passwordVisible = revealedPasswordIds.has(item.cipherId);
                return <article className="password-security-item" key={item.cipherId}>
                  <div className="password-security-item-main">
                    <div className="password-security-item-header">
                      <strong>{name || t('txt_no_name')}</strong>
                      <div className="password-security-badges">
                        {item.exposedCount === null && <span className="risk-badge muted">{t('txt_password_security_not_checked')}</span>}
                        {(item.exposedCount || 0) > 0 && <span className="risk-badge danger">{t('txt_password_security_exposed_short', { count: item.exposedCount || 0 })}</span>}
                        {item.weak && <span className="risk-badge weak">{t('txt_password_security_weak_short')}</span>}
                        {item.reusedCount > 1 && <span className="risk-badge reused">{t('txt_password_security_reused_short')}</span>}
                      </div>
                    </div>
                    <span className="password-security-password">{passwordVisible ? password : maskSecret(password)}</span>
                  </div>
                  <div className="password-security-item-actions">
                    <button type="button" className="btn btn-secondary small" onClick={() => togglePasswordVisibility(item.cipherId)}>
                      {passwordVisible ? <EyeOff size={14} className="btn-icon" /> : <Eye size={14} className="btn-icon" />}
                      {passwordVisible ? t('txt_hide') : t('txt_reveal')}
                    </button>
                    <Link href={`/vault?cipher=${encodeURIComponent(item.cipherId)}`} className="btn btn-secondary small password-security-open">
                      <ExternalLink size={14} className="btn-icon" />{t('txt_password_security_jump')}
                    </Link>
                  </div>
                </article>;
              })}
            </div>
          )}
        </section>
      )}
    </section>
  );
}

function SecurityMetric(props: { icon: preact.ComponentChildren; tone: 'danger' | 'warning' | 'primary'; label: string; value: string | number; active: boolean; disabled: boolean; onClick: () => void }) {
  return <button type="button" className={`password-security-metric ${props.tone}`} aria-pressed={props.active} disabled={props.disabled} onClick={props.onClick}><span>{props.icon}</span><div><strong>{props.value}</strong><small>{props.label}</small></div></button>;
}
