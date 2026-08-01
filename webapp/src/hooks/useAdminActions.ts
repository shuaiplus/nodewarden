import { useMemo } from 'preact/hooks';
import { createInvite, deleteAllInvites, deleteInvalidInvites, deleteInvite, deleteUser, setUserStatus } from '@/lib/api/admin';
import { deriveLoginHash } from '@/lib/api/auth';
import { t } from '@/lib/i18n';
import type { AppConfirmState } from '@/components/AppGlobalOverlays';
import type { AuthedFetch } from '@/lib/api/shared';

type Notify = (type: 'success' | 'error' | 'warning', text: string) => void;

interface UseAdminActionsOptions {
  authedFetch: AuthedFetch;
  email: string;
  defaultKdfIterations: number;
  onNotify: Notify;
  onSetConfirm: (next: AppConfirmState | null) => void;
  refetchUsers: () => Promise<unknown>;
  refetchInvites: () => Promise<unknown>;
}

export default function useAdminActions(options: UseAdminActionsOptions) {
  const {
    authedFetch,
    email,
    defaultKdfIterations,
    onNotify,
    onSetConfirm,
    refetchUsers,
    refetchInvites,
  } = options;

  async function withMasterPasswordHash(masterPassword: string | undefined): Promise<string> {
    const normalizedEmail = String(email || '').trim().toLowerCase();
    const normalizedPassword = String(masterPassword || '');
    if (!normalizedEmail) throw new Error(t('txt_profile_unavailable'));
    if (!normalizedPassword.trim()) throw new Error(t('txt_master_password_is_required'));
    const derived = await deriveLoginHash(normalizedEmail, normalizedPassword, defaultKdfIterations);
    return derived.hash;
  }

  return useMemo(
    () => ({
      refreshAdmin() {
        void Promise.all([refetchUsers(), refetchInvites()]).catch((error) => {
          onNotify('error', error instanceof Error ? error.message : t('txt_load_admin_data_failed'));
        });
      },

      async createInvite(hours: number) {
        onSetConfirm({
          title: t('txt_create_timed_invite'),
          message: t('txt_enter_master_password_to_continue'),
          requireMasterPassword: true,
          onConfirm: (masterPassword) => {
            onSetConfirm(null);
            void (async () => {
              try {
                const hash = await withMasterPasswordHash(masterPassword);
                await createInvite(authedFetch, hours, hash);
                await refetchInvites();
                onNotify('success', t('txt_invite_created'));
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_create_invite_failed'));
              }
            })();
          },
        });
      },

      async toggleUserStatus(userId: string, status: 'active' | 'banned') {
        const nextStatus = status === 'active' ? 'banned' : 'active';
        onSetConfirm({
          title: nextStatus === 'banned' ? t('txt_ban') : t('txt_unban'),
          message: t('txt_enter_master_password_to_continue'),
          danger: nextStatus === 'banned',
          requireMasterPassword: true,
          onConfirm: (masterPassword) => {
            onSetConfirm(null);
            void (async () => {
              try {
                const hash = await withMasterPasswordHash(masterPassword);
                await setUserStatus(authedFetch, userId, nextStatus, hash);
                await refetchUsers();
                onNotify('success', t('txt_user_status_updated'));
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_update_user_status_failed'));
              }
            })();
          },
        });
      },

      async deleteInvite(code: string) {
        onSetConfirm({
          title: t('txt_delete_invite'),
          message: `${t('txt_delete_invite_confirm_message')}\n${t('txt_enter_master_password_to_continue')}`,
          danger: true,
          requireMasterPassword: true,
          onConfirm: (masterPassword) => {
            onSetConfirm(null);
            void (async () => {
              try {
                const hash = await withMasterPasswordHash(masterPassword);
                await deleteInvite(authedFetch, code, hash);
                await refetchInvites();
                onNotify('success', t('txt_invite_deleted'));
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_delete_invite_failed'));
              }
            })();
          },
        });
      },

      async deleteInvalidInvites() {
        onSetConfirm({
          title: t('txt_delete_invalid_invites'),
          message: `${t('txt_delete_invalid_invites_confirm_message')}\n${t('txt_enter_master_password_to_continue')}`,
          danger: true,
          requireMasterPassword: true,
          onConfirm: (masterPassword) => {
            onSetConfirm(null);
            void (async () => {
              try {
                const hash = await withMasterPasswordHash(masterPassword);
                await deleteInvalidInvites(authedFetch, hash);
                await refetchInvites();
                onNotify('success', t('txt_invalid_invites_deleted'));
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_delete_invalid_invites_failed'));
              }
            })();
          },
        });
      },

      async deleteAllInvites() {
        onSetConfirm({
          title: t('txt_delete_all_invites'),
          message: `${t('txt_delete_all_invite_codes_active_inactive')}\n${t('txt_enter_master_password_to_continue')}`,
          danger: true,
          requireMasterPassword: true,
          onConfirm: (masterPassword) => {
            onSetConfirm(null);
            void (async () => {
              try {
                const hash = await withMasterPasswordHash(masterPassword);
                await deleteAllInvites(authedFetch, hash);
                await refetchInvites();
                onNotify('success', t('txt_all_invites_deleted'));
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_delete_all_invites_failed'));
              }
            })();
          },
        });
      },

      async deleteUser(userId: string) {
        onSetConfirm({
          title: t('txt_delete_user'),
          message: `${t('txt_delete_this_user_and_all_user_data')}\n${t('txt_enter_master_password_to_continue')}`,
          danger: true,
          requireMasterPassword: true,
          onConfirm: (masterPassword) => {
            onSetConfirm(null);
            void (async () => {
              try {
                const hash = await withMasterPasswordHash(masterPassword);
                await deleteUser(authedFetch, userId, hash);
                await refetchUsers();
                onNotify('success', t('txt_user_deleted'));
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_delete_user_failed'));
              }
            })();
          },
        });
      },
    }),
    [authedFetch, defaultKdfIterations, email, onNotify, onSetConfirm, refetchInvites, refetchUsers]
  );
}
