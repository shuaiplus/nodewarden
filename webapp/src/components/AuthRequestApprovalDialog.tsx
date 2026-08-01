import { ShieldCheck, ShieldX } from 'lucide-preact';
import ConfirmDialog from '@/components/ConfirmDialog';
import { t } from '@/lib/i18n';
import type { AuthRequest } from '@/lib/types';

interface AuthRequestApprovalDialogProps {
  open: boolean;
  authRequest: AuthRequest | null;
  submitting: boolean;
  onApprove: () => void;
  onDeny: () => void;
  onClose: () => void;
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) return t('txt_dash');
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

export default function AuthRequestApprovalDialog(props: AuthRequestApprovalDialogProps) {
  const authRequest = props.authRequest;
  return (
    <ConfirmDialog
      open={props.open && !!authRequest}
      title={t('txt_approve_device_login')}
      message={t('txt_auth_request_approve_message')}
      confirmText={props.submitting ? t('txt_approving') : t('txt_approve')}
      cancelText={t('txt_later')}
      confirmDisabled={props.submitting || !authRequest}
      cancelDisabled={props.submitting}
      onConfirm={props.onApprove}
      onCancel={props.onClose}
      afterActions={(
        <button
          type="button"
          className="btn btn-danger dialog-btn"
          disabled={props.submitting || !authRequest}
          onClick={props.onDeny}
        >
          <ShieldX size={14} className="btn-icon" />
          {t('txt_deny')}
        </button>
      )}
    >
      {authRequest && (
        <div className="auth-request-details">
          <div className="auth-request-device">
            <ShieldCheck size={18} />
            <div>
              <strong>{authRequest.requestDeviceType || t('txt_unknown_device')}</strong>
              <small>{authRequest.requestDeviceIdentifier}</small>
            </div>
          </div>
          <div className="auth-request-kv">
            <span>{t('txt_created')}</span>
            <strong>{formatDateTime(authRequest.creationDate)}</strong>
          </div>
          {authRequest.requestIpAddress && (
            <div className="auth-request-kv">
              <span>{t('txt_ip_address')}</span>
              <strong>{authRequest.requestIpAddress}</strong>
            </div>
          )}
          <div className="auth-request-fingerprint">
            <span>{t('txt_fingerprint_phrase')}</span>
            <strong>{authRequest.fingerprintPhrase || t('txt_dash')}</strong>
          </div>
        </div>
      )}
    </ConfirmDialog>
  );
}
