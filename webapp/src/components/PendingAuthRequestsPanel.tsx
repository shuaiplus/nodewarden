import { useState } from 'preact/hooks';
import { RefreshCw, ShieldCheck, ShieldX } from 'lucide-preact';
import LoadingState from '@/components/LoadingState';
import type { AuthRequest } from '@/lib/types';
import { t } from '@/lib/i18n';

interface PendingAuthRequestsPanelProps {
  pendingAuthRequests: AuthRequest[];
  pendingAuthRequestsLoading: boolean;
  pendingAuthRequestsRefreshing?: boolean;
  onRefreshPendingAuthRequests: () => Promise<void>;
  onApproveAuthRequest: (request: AuthRequest) => Promise<void>;
  onDenyAuthRequest: (request: AuthRequest) => Promise<void>;
  className?: string;
  loadingVariant?: 'placeholder' | 'compact';
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) return t('txt_dash');
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? t('txt_dash') : date.toLocaleString();
}

export default function PendingAuthRequestsPanel(props: PendingAuthRequestsPanelProps) {
  const [authRequestSubmittingId, setAuthRequestSubmittingId] = useState<string | null>(null);
  const refreshing = props.pendingAuthRequestsLoading || !!props.pendingAuthRequestsRefreshing;

  async function approveAuthRequest(authRequest: AuthRequest): Promise<void> {
    if (authRequestSubmittingId) return;
    setAuthRequestSubmittingId(authRequest.id);
    try {
      await props.onApproveAuthRequest(authRequest);
    } finally {
      setAuthRequestSubmittingId(null);
    }
  }

  async function denyAuthRequest(authRequest: AuthRequest): Promise<void> {
    if (authRequestSubmittingId) return;
    setAuthRequestSubmittingId(authRequest.id);
    try {
      await props.onDenyAuthRequest(authRequest);
    } finally {
      setAuthRequestSubmittingId(null);
    }
  }

  return (
    <section className={props.className || 'card settings-module'}>
      <div className="settings-module-head">
        <h3>{t('txt_pending_device_logins')}</h3>
        <button
          type="button"
          className="btn btn-secondary small"
          disabled={refreshing}
          onClick={() => void props.onRefreshPendingAuthRequests()}
        >
          <RefreshCw size={14} className={`btn-icon${refreshing ? ' btn-icon-spin' : ''}`} />
          {t('txt_refresh')}
        </button>
      </div>
      <div className="account-passkeys-list">
        {props.pendingAuthRequestsLoading && props.pendingAuthRequests.length === 0 ? (
          props.loadingVariant === 'compact' ? (
            <LoadingState lines={2} compact />
          ) : (
            <div className="settings-module-placeholder">
              <RefreshCw size={20} />
              <span>{t('txt_loading')}</span>
            </div>
          )
        ) : props.pendingAuthRequests.length === 0 ? (
          <div className="settings-module-placeholder">
            <ShieldCheck size={20} />
            <span>{t('txt_no_pending_device_logins')}</span>
          </div>
        ) : (
          props.pendingAuthRequests.map((authRequest) => (
            <div key={authRequest.id} className="account-passkey-row auth-request-row">
              <div className="account-passkey-main">
                <strong>{authRequest.requestDeviceType || t('txt_unknown_device')}</strong>
                <small>{authRequest.requestDeviceIdentifier}</small>
                <small>{t('txt_created_value', { value: formatDateTime(authRequest.creationDate) })}</small>
              </div>
              <span className="auth-request-fingerprint-inline">
                {authRequest.fingerprintPhrase || t('txt_dash')}
              </span>
              <div className="actions account-passkey-actions">
                <button
                  type="button"
                  className="btn btn-primary small"
                  disabled={!!authRequestSubmittingId}
                  onClick={() => void approveAuthRequest(authRequest)}
                >
                  <ShieldCheck size={14} className="btn-icon" />
                  {authRequestSubmittingId === authRequest.id ? t('txt_approving') : t('txt_approve')}
                </button>
                <button
                  type="button"
                  className="btn btn-danger small"
                  disabled={!!authRequestSubmittingId}
                  onClick={() => void denyAuthRequest(authRequest)}
                >
                  <ShieldX size={14} className="btn-icon" />
                  {t('txt_deny')}
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
