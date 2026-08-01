import { useState } from 'preact/hooks';
import { CheckSquare, Clock3, Pencil, RefreshCw, ShieldCheck, ShieldOff, Trash2 } from 'lucide-preact';
import ConfirmDialog from '@/components/ConfirmDialog';
import LoadingState from '@/components/LoadingState';
import PendingAuthRequestsPanel from '@/components/PendingAuthRequestsPanel';
import type { AuthRequest, AuthorizedDevice } from '@/lib/types';
import { t } from '@/lib/i18n';

interface SecurityDevicesPageProps {
  devices: AuthorizedDevice[];
  currentDeviceIdentifier: string;
  loading: boolean;
  error: string;
  pendingAuthRequests: AuthRequest[];
  pendingAuthRequestsLoading: boolean;
  pendingAuthRequestsRefreshing: boolean;
  onRefresh: () => void;
  onRefreshPendingAuthRequests: () => Promise<void>;
  onApproveAuthRequest: (request: AuthRequest) => Promise<void>;
  onDenyAuthRequest: (request: AuthRequest) => Promise<void>;
  onRenameDevice: (device: AuthorizedDevice, name: string) => Promise<void>;
  onRevokeTrust: (device: AuthorizedDevice) => void;
  onTrustPermanently: (device: AuthorizedDevice) => void;
  onRemoveDevice: (device: AuthorizedDevice) => void;
  onRemoveSelectedDevices: (devices: AuthorizedDevice[]) => void;
  onRevokeAll: () => void;
  onRemoveAll: () => void;
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) return t('txt_dash');
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return t('txt_dash');
  return date.toLocaleString();
}

function isPermanentTrust(value: string | null | undefined): boolean {
  if (!value) return false;
  const date = new Date(value);
  return !Number.isNaN(date.getTime()) && date.getUTCFullYear() >= 2099;
}

function mapDeviceTypeName(type: number): string {
  switch (type) {
    case 0: return t('txt_android');
    case 1: return t('txt_ios');
    case 2: return t('txt_chrome_extension');
    case 3: return t('txt_firefox_extension');
    case 4: return t('txt_opera_extension');
    case 5: return t('txt_edge_extension');
    case 6: return t('txt_windows_desktop');
    case 7: return t('txt_macos_desktop');
    case 8: return t('txt_linux_desktop');
    case 9: return t('txt_chrome_browser');
    case 10: return t('txt_firefox_browser');
    case 11: return t('txt_opera_browser');
    case 12: return t('txt_edge_browser');
    case 13: return t('txt_ie_browser');
    case 14: return t('txt_web');
    default: return t('txt_type_type', { type });
  }
}

export default function SecurityDevicesPage(props: SecurityDevicesPageProps) {
  const [editingDevice, setEditingDevice] = useState<AuthorizedDevice | null>(null);
  const [deviceNote, setDeviceNote] = useState('');
  const [savingNote, setSavingNote] = useState(false);
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<string[]>([]);
  const currentDeviceIdentifier = props.currentDeviceIdentifier;
  const selectableDevices = props.devices.filter((device) => (
    device.identifier !== currentDeviceIdentifier
  ));
  const selectedDeviceIdSet = new Set(selectedDeviceIds);
  const selectedDevices = selectableDevices.filter((device) => selectedDeviceIdSet.has(device.identifier));
  const allSelectableSelected = selectableDevices.length > 0 && selectedDevices.length === selectableDevices.length;

  async function handleSaveDeviceNote(): Promise<void> {
    if (!editingDevice || savingNote) return;
    setSavingNote(true);
    try {
      await props.onRenameDevice(editingDevice, deviceNote);
      setEditingDevice(null);
      setDeviceNote('');
    } finally {
      setSavingNote(false);
    }
  }

  function toggleSelectAllDevices(): void {
    setSelectedDeviceIds(allSelectableSelected ? [] : selectableDevices.map((device) => device.identifier));
  }

  function toggleSelectedDevice(device: AuthorizedDevice): void {
    if (device.identifier === currentDeviceIdentifier) return;
    setSelectedDeviceIds((current) => (
      current.includes(device.identifier)
        ? current.filter((id) => id !== device.identifier)
        : [...current, device.identifier]
    ));
  }

  return (
    <>
      <div className="stack">
        <PendingAuthRequestsPanel
          className="card"
          loadingVariant="compact"
          pendingAuthRequests={props.pendingAuthRequests}
          pendingAuthRequestsLoading={props.pendingAuthRequestsLoading}
          pendingAuthRequestsRefreshing={props.pendingAuthRequestsRefreshing}
          onRefreshPendingAuthRequests={props.onRefreshPendingAuthRequests}
          onApproveAuthRequest={props.onApproveAuthRequest}
          onDenyAuthRequest={props.onDenyAuthRequest}
        />

        <section className="card">
          <div className="section-head">
            <div>
              <h3 className="flush-title">{t('txt_authorized_devices')}</h3>
              <div className="muted-inline section-note">
                {t('txt_manage_device_sessions_and_30_day_totp_trusted_sessions')}
              </div>
            </div>
            <div className="actions">
              <button type="button" className="btn btn-secondary small" disabled={props.loading} onClick={props.onRefresh}>
                <RefreshCw size={14} className="btn-icon" />
                {t('txt_refresh')}
              </button>
              <button
                type="button"
                className="btn btn-secondary small"
                disabled={props.loading || selectableDevices.length === 0}
                onClick={toggleSelectAllDevices}
              >
                <CheckSquare size={14} className="btn-icon" />
                {allSelectableSelected ? t('txt_clear_selection') : t('txt_select_all')}
              </button>
              <button
                type="button"
                className="btn btn-danger small"
                disabled={selectedDevices.length === 0}
                onClick={() => {
                  props.onRemoveSelectedDevices(selectedDevices);
                  setSelectedDeviceIds([]);
                }}
              >
                <Trash2 size={14} className="btn-icon" />
                {t('txt_remove_selected_devices', { count: selectedDevices.length })}
              </button>
              <button type="button" className="btn btn-danger small" onClick={props.onRevokeAll}>
                <ShieldOff size={14} className="btn-icon" />
                {t('txt_revoke_all_trusted')}
              </button>
              <button type="button" className="btn btn-danger small" onClick={props.onRemoveAll}>
                <Trash2 size={14} className="btn-icon" />
                {t('txt_remove_all_devices')}
              </button>
            </div>
          </div>
          {!!props.error && (
            <div className="local-error">
              <span>{props.error}</span>
              <button type="button" className="btn btn-secondary small" disabled={props.loading} onClick={props.onRefresh}>
                <RefreshCw size={14} className="btn-icon" />
                {t('txt_refresh')}
              </button>
            </div>
          )}
          <table className="table authorized-devices-table">
          <colgroup>
            <col className="authorized-devices-col-select" />
            <col className="authorized-devices-col-device" />
            <col className="authorized-devices-col-type" />
            <col className="authorized-devices-col-status" />
            <col className="authorized-devices-col-date" />
            <col className="authorized-devices-col-date" />
            <col className="authorized-devices-col-trust" />
            <col className="authorized-devices-col-actions" />
          </colgroup>
          <thead>
            <tr>
              <th>{t('txt_select')}</th>
              <th>{t('txt_device')}</th>
              <th>{t('txt_type')}</th>
              <th>{t('txt_status')}</th>
              <th>{t('txt_added')}</th>
              <th>{t('txt_last_seen')}</th>
              <th>{t('txt_trusted_until')}</th>
              <th>{t('txt_actions')}</th>
            </tr>
          </thead>
          <tbody>
            {props.devices.map((device) => (
              <tr key={device.identifier}>
                <td data-label={t('txt_select')}>
                  <input
                    type="checkbox"
                    className="authorized-device-checkbox"
                    checked={selectedDeviceIdSet.has(device.identifier)}
                    disabled={device.identifier === currentDeviceIdentifier}
                    aria-label={t('txt_select_device_name', { name: device.name || t('txt_unknown_device') })}
                    onChange={() => toggleSelectedDevice(device)}
                  />
                </td>
                <td data-label={t('txt_device')}>
                  <div>{device.name || t('txt_unknown_device')}</div>
                  {!!device.deviceNote && !!device.systemName && device.systemName !== device.name && (
                    <div className="muted-inline">{device.systemName}</div>
                  )}
                  <div className="muted-inline">{device.identifier}</div>
                </td>
                <td data-label={t('txt_type')}>{mapDeviceTypeName(device.type)}</td>
                <td data-label={t('txt_status')}>
                  <span className={`device-status-pill ${device.online ? 'online' : 'offline'}`}>
                    {device.online ? t('txt_online') : t('txt_offline')}
                  </span>
                </td>
                <td data-label={t('txt_added')}>{formatDateTime(device.creationDate)}</td>
                <td data-label={t('txt_last_seen')}>{formatDateTime(device.lastSeenAt || device.revisionDate)}</td>
                <td data-label={t('txt_trusted_until')}>
                  {device.trusted ? (
                    <div className="trusted-cell">
                      <Clock3 size={13} />
                      <span>{isPermanentTrust(device.trustedUntil) ? t('txt_permanent_trust') : formatDateTime(device.trustedUntil)}</span>
                    </div>
                  ) : (
                    <span className="muted-inline">{t('txt_not_trusted')}</span>
                  )}
                </td>
                <td data-label={t('txt_actions')}>
                  <div className="actions authorized-devices-actions">
                    <button
                      type="button"
                      className="btn btn-secondary small"
                      disabled={!device.trusted}
                      onClick={() => props.onRevokeTrust(device)}
                    >
                      <ShieldOff size={14} className="btn-icon" />
                      {t('txt_untrust')}
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary small"
                      disabled={!device.trusted || !device.trustedUntil || isPermanentTrust(device.trustedUntil)}
                      onClick={() => props.onTrustPermanently(device)}
                    >
                      <ShieldCheck size={14} className="btn-icon" />
                      {t('txt_trust_permanently')}
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary small"
                      disabled={device.hasStoredDevice === false}
                      onClick={() => {
                        setEditingDevice(device);
                        setDeviceNote(device.deviceNote || device.name || '');
                      }}
                    >
                      <Pencil size={14} className="btn-icon" />
                      {t('txt_device_note')}
                    </button>
                    <button
                      type="button"
                      className="btn btn-danger small"
                      disabled={device.hasStoredDevice === false}
                      onClick={() => props.onRemoveDevice(device)}
                    >
                      <Trash2 size={14} className="btn-icon" />
                      {t('txt_delete')}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {props.loading && props.devices.length === 0 && (
              <tr>
                <td colSpan={8}>
                  <LoadingState lines={5} compact />
                </td>
              </tr>
            )}
            {!props.loading && props.devices.length === 0 && (
              <tr>
                <td colSpan={8}>
                  <div className="empty empty-comfortable">{t('txt_no_devices_found')}</div>
                </td>
              </tr>
            )}
          </tbody>
          </table>
        </section>
      </div>

      <ConfirmDialog
        open={!!editingDevice}
        title={t('txt_device_note')}
        message={t('txt_replace_device_name_with_note')}
        confirmText={t('txt_save')}
        cancelText={t('txt_cancel')}
        showIcon={false}
        confirmDisabled={savingNote}
        cancelDisabled={savingNote}
        onConfirm={() => void handleSaveDeviceNote()}
        onCancel={() => {
          if (savingNote) return;
          setEditingDevice(null);
          setDeviceNote('');
        }}
      >
        <label className="field">
          <span>{t('txt_device_note')}</span>
          <input
            className="input"
            maxLength={128}
            value={deviceNote}
            onInput={(e) => setDeviceNote((e.currentTarget as HTMLInputElement).value)}
          />
        </label>
      </ConfirmDialog>
    </>
  );
}
