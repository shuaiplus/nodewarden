import { useMemo, useState } from 'preact/hooks';
import { AlertTriangle, Copy, RefreshCw } from 'lucide-preact';
import { copyTextToClipboard } from '@/lib/clipboard';
import StandalonePageFrame from '@/components/StandalonePageFrame';
import { t } from '@/lib/i18n';

interface JwtWarningPageProps {
  reason: 'missing' | 'too_short';
  minLength: number;
}

const CLOUDFLARE_SETTINGS_URL =
  'https://dash.cloudflare.com/?to=/:account/workers/services/view/nodewarden/production/settings';

export default function JwtWarningPage(props: JwtWarningPageProps) {
  const [seed, setSeed] = useState(0);
  const [copyHint, setCopyHint] = useState('');

  const generatedSecret = useMemo(() => generateJwtSecret(32), [seed]);

  const title =
    props.reason === 'missing'
      ? t('txt_jwt_title_missing')
      : t('txt_jwt_title_too_short');

  const isMissing = props.reason === 'missing';
  const fixTitle = isMissing ? t('txt_jwt_how_to_fix_add') : t('txt_jwt_how_to_fix_replace');
  const fixStep1 = isMissing ? t('txt_jwt_add_step_1') : t('txt_jwt_replace_step_1', { min: props.minLength });
  const fixStep2Prefix = isMissing ? t('txt_jwt_add_step_2_prefix') : t('txt_jwt_replace_step_2_prefix');
  const fixStep2Suffix = isMissing ? t('txt_jwt_add_step_2_suffix') : t('txt_jwt_replace_step_2_suffix');
  const fixStep3 = isMissing ? t('txt_jwt_add_step_3') : t('txt_jwt_replace_step_3');

  return (
    <div className="auth-page">
      <StandalonePageFrame title={title}>
        <div className="jwt-warning-head">
          <AlertTriangle size={20} />
          <strong>{t('txt_jwt_warning_subtitle')}</strong>
        </div>

        <div className="jwt-warning-box">
          <div className="jwt-warning-label">{t('txt_jwt_what_is')}</div>
          <p className="jwt-warning-copy">{t('txt_jwt_what_is_body')}</p>

          <div className="jwt-warning-label">{fixTitle}</div>
          <ol className="jwt-warning-list">
            <li>{fixStep1}</li>
            <li>
              {fixStep2Prefix}
              <a
                href={CLOUDFLARE_SETTINGS_URL}
                className="jwt-inline-link"
                target="_blank"
                rel="noreferrer"
              >
                {t('txt_settings')}
              </a>
              {fixStep2Suffix}
              <div className="jwt-secret-fields">
                <div className="jwt-secret-row">
                  <span>{t('txt_jwt_secret_type_label')}</span>
                  <strong>{t('txt_jwt_secret_type_value')}</strong>
                </div>
                <div className="jwt-secret-row">
                  <span>{t('txt_jwt_secret_name_label')}</span>
                  <strong>JWT_SECRET</strong>
                </div>
                <div className="jwt-secret-row">
                  <span>{t('txt_jwt_secret_value_label')}</span>
                  <strong>{t('txt_jwt_secret_value_requirement', { min: props.minLength })}</strong>
                </div>
              </div>
            </li>
            <li>{fixStep3}</li>
          </ol>

          <div className="jwt-generator">
            <div className="jwt-warning-label">{t('txt_random_secret_generator')}</div>
            <input className="input input-readonly" readOnly value={generatedSecret} />
            <div className="jwt-generator-actions">
              <button type="button" className="btn btn-primary" onClick={() => setSeed((v) => v + 1)}>
                <RefreshCw size={15} className="btn-icon" />
                {t('txt_regenerate')}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={async () => {
                  await copyTextToClipboard(generatedSecret, {
                    onSuccess: () => setCopyHint(t('txt_copied')),
                    onError: () => setCopyHint(t('txt_copy_failed')),
                  });
                  window.setTimeout(() => setCopyHint(''), 1500);
                }}
              >
                <Copy size={15} className="btn-icon" />
                {t('txt_copy')}
              </button>
              {copyHint && <span className="jwt-copy-hint">{copyHint}</span>}
            </div>
          </div>
        </div>
      </StandalonePageFrame>
    </div>
  );
}

function generateJwtSecret(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let out = '';
  const maxUnbiasedByte = Math.floor(256 / chars.length) * chars.length;
  while (out.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    for (const value of bytes) {
      if (value >= maxUnbiasedByte) continue;
      out += chars[value % chars.length];
      if (out.length >= length) break;
    }
  }
  return out;
}
