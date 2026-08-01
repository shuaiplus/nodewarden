import ConfirmDialog from '@/components/ConfirmDialog';
import type { CustomFieldType, Folder } from '@/lib/types';
import { getFieldTypeOptions, toBooleanFieldValue } from '@/components/vault/vault-page-helpers';
import { t } from '@/lib/i18n';

interface VaultDialogsProps {
  busy: boolean;
  fieldModalOpen: boolean;
  fieldType: CustomFieldType;
  fieldLabel: string;
  fieldValue: string;
  archiveConfirmOpen: boolean;
  bulkArchiveOpen: boolean;
  pendingDeleteOpen: boolean;
  bulkDeleteOpen: boolean;
  sidebarTrashMode: boolean;
  selectedCount: number;
  moveOpen: boolean;
  moveFolderId: string;
  folders: Folder[];
  createFolderOpen: boolean;
  newFolderName: string;
  renameFolderOpen: boolean;
  renameFolderName: string;
  pendingDeleteFolder: Folder | null;
  deleteAllFoldersOpen: boolean;
  repromptOpen: boolean;
  repromptPassword: string;
  deletePasskeyOpen: boolean;
  onConfirmAddField: () => void;
  onCancelFieldModal: () => void;
  onFieldTypeChange: (value: CustomFieldType) => void;
  onFieldLabelChange: (value: string) => void;
  onFieldValueChange: (value: string) => void;
  onConfirmArchive: () => void;
  onCancelArchive: () => void;
  onConfirmBulkArchive: () => void;
  onCancelBulkArchive: () => void;
  onConfirmDelete: () => void;
  onCancelDelete: () => void;
  onConfirmBulkDelete: () => void;
  onCancelBulkDelete: () => void;
  onConfirmMove: () => void;
  onCancelMove: () => void;
  onMoveFolderIdChange: (value: string) => void;
  onConfirmCreateFolder: () => void;
  onCancelCreateFolder: () => void;
  onNewFolderNameChange: (value: string) => void;
  onConfirmRenameFolder: () => void;
  onCancelRenameFolder: () => void;
  onRenameFolderNameChange: (value: string) => void;
  onConfirmDeleteFolder: () => void;
  onCancelDeleteFolder: () => void;
  onConfirmDeleteAllFolders: () => void;
  onCancelDeleteAllFolders: () => void;
  onConfirmReprompt: () => void;
  onCancelReprompt: () => void;
  onRepromptPasswordChange: (value: string) => void;
  onConfirmDeletePasskey: () => void;
  onCancelDeletePasskey: () => void;
}

export default function VaultDialogs(props: VaultDialogsProps) {
  const fieldTypeOptions = getFieldTypeOptions();
  return (
    <>
      <ConfirmDialog
        open={props.fieldModalOpen}
        title={t('txt_add_field')}
        message={t('txt_configure_custom_field_values')}
        confirmText={t('txt_add')}
        cancelText={t('txt_cancel')}
        onConfirm={props.onConfirmAddField}
        onCancel={props.onCancelFieldModal}
      >
        <label className="field">
          <span>{t('txt_field_type')}</span>
          <select className="input" value={props.fieldType} onInput={(e) => props.onFieldTypeChange(Number((e.currentTarget as HTMLSelectElement).value) as CustomFieldType)}>
            {fieldTypeOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>{t('txt_field_label')}</span>
          <input className="input" value={props.fieldLabel} onInput={(e) => props.onFieldLabelChange((e.currentTarget as HTMLInputElement).value)} />
        </label>
        {props.fieldType === 2 ? (
          <label className="check-line">
            <input
              type="checkbox"
              checked={toBooleanFieldValue(props.fieldValue)}
              onInput={(e) => props.onFieldValueChange((e.currentTarget as HTMLInputElement).checked ? 'true' : 'false')}
            />
            {t('txt_enabled')}
          </label>
        ) : (
          <label className="field">
            <span>{t('txt_field_value')}</span>
            <textarea
              className="input textarea custom-field-textarea"
              value={props.fieldValue}
              onInput={(e) => props.onFieldValueChange((e.currentTarget as HTMLTextAreaElement).value)}
            />
          </label>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={props.archiveConfirmOpen}
        title={t('txt_archive_item')}
        message={t('txt_archive_item_message')}
        confirmText={t('txt_archive')}
        cancelText={t('txt_cancel')}
        confirmDisabled={props.busy}
        cancelDisabled={props.busy}
        onConfirm={props.onConfirmArchive}
        onCancel={props.onCancelArchive}
      />

      <ConfirmDialog
        open={props.bulkArchiveOpen}
        title={t('txt_archive_selected_items')}
        message={t('txt_archive_selected_items_message', { count: props.selectedCount })}
        confirmText={t('txt_archive')}
        cancelText={t('txt_cancel')}
        confirmDisabled={props.busy}
        cancelDisabled={props.busy}
        onConfirm={props.onConfirmBulkArchive}
        onCancel={props.onCancelBulkArchive}
      />

      <ConfirmDialog
        open={props.pendingDeleteOpen}
        title={t('txt_delete_item')}
        message={t('txt_are_you_sure_you_want_to_delete_this_item')}
        danger
        confirmDisabled={props.busy}
        cancelDisabled={props.busy}
        onConfirm={props.onConfirmDelete}
        onCancel={props.onCancelDelete}
      />

      <ConfirmDialog
        open={props.bulkDeleteOpen}
        title={props.sidebarTrashMode ? t('txt_delete_selected_items_permanently') : t('txt_delete_selected_items')}
        message={
          props.sidebarTrashMode
            ? t('txt_are_you_sure_you_want_to_delete_count_selected_items_permanently', { count: props.selectedCount })
            : t('txt_are_you_sure_you_want_to_delete_count_selected_items', { count: props.selectedCount })
        }
        danger
        confirmDisabled={props.busy}
        cancelDisabled={props.busy}
        onConfirm={props.onConfirmBulkDelete}
        onCancel={props.onCancelBulkDelete}
      />

      <ConfirmDialog
        open={props.moveOpen}
        title={t('txt_move_selected_items')}
        message={t('txt_choose_destination_folder')}
        confirmText={t('txt_move')}
        cancelText={t('txt_cancel')}
        confirmDisabled={props.busy}
        cancelDisabled={props.busy}
        onConfirm={props.onConfirmMove}
        onCancel={props.onCancelMove}
      >
        <label className="field">
          <span>{t('txt_folder')}</span>
          <select className="input" value={props.moveFolderId} onInput={(e) => props.onMoveFolderIdChange((e.currentTarget as HTMLSelectElement).value)}>
            <option value="__none__">{t('txt_no_folder')}</option>
            {props.folders.map((folder) => (
              <option key={folder.id} value={folder.id}>
                {folder.decName || folder.name || folder.id}
              </option>
            ))}
          </select>
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={props.createFolderOpen}
        title={t('txt_create_folder')}
        message={t('txt_enter_a_folder_name')}
        confirmText={t('txt_create')}
        cancelText={t('txt_cancel')}
        confirmDisabled={props.busy}
        cancelDisabled={props.busy}
        onConfirm={props.onConfirmCreateFolder}
        onCancel={props.onCancelCreateFolder}
      >
        <label className="field">
          <span>{t('txt_folder_name')}</span>
          <input className="input" value={props.newFolderName} onInput={(e) => props.onNewFolderNameChange((e.currentTarget as HTMLInputElement).value)} />
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={props.renameFolderOpen}
        title={t('txt_edit')}
        message={t('txt_enter_a_folder_name')}
        confirmText={t('txt_save')}
        cancelText={t('txt_cancel')}
        confirmDisabled={props.busy}
        cancelDisabled={props.busy}
        onConfirm={props.onConfirmRenameFolder}
        onCancel={props.onCancelRenameFolder}
      >
        <label className="field">
          <span>{t('txt_folder_name')}</span>
          <input className="input" value={props.renameFolderName} onInput={(e) => props.onRenameFolderNameChange((e.currentTarget as HTMLInputElement).value)} />
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={!!props.pendingDeleteFolder}
        title={t('txt_delete_folder')}
        message={t('txt_delete_folder_message', { name: props.pendingDeleteFolder?.decName || props.pendingDeleteFolder?.name || props.pendingDeleteFolder?.id || '' })}
        confirmText={t('txt_delete')}
        cancelText={t('txt_cancel')}
        danger
        confirmDisabled={props.busy}
        cancelDisabled={props.busy}
        onConfirm={props.onConfirmDeleteFolder}
        onCancel={props.onCancelDeleteFolder}
      />

      <ConfirmDialog
        open={props.deleteAllFoldersOpen}
        title={t('txt_delete_all_folders')}
        message={t('txt_delete_all_folders_message')}
        confirmText={t('txt_delete')}
        cancelText={t('txt_cancel')}
        danger
        confirmDisabled={props.busy}
        cancelDisabled={props.busy}
        onConfirm={props.onConfirmDeleteAllFolders}
        onCancel={props.onCancelDeleteAllFolders}
      />

      <ConfirmDialog
        open={props.repromptOpen}
        title={t('txt_unlock_item')}
        message={t('txt_enter_master_password_to_view_this_item')}
        confirmText={t('txt_unlock')}
        cancelText={t('txt_cancel')}
        showIcon={false}
        confirmDisabled={props.busy}
        cancelDisabled={props.busy}
        onConfirm={props.onConfirmReprompt}
        onCancel={props.onCancelReprompt}
      >
        <label className="field">
          <span>{t('txt_master_password')}</span>
          <input className="input" type="password" value={props.repromptPassword} onInput={(e) => props.onRepromptPasswordChange((e.currentTarget as HTMLInputElement).value)} />
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={props.deletePasskeyOpen}
        title={t('txt_delete_passkey')}
        message={t('txt_are_you_sure_you_want_to_delete_this_passkey')}
        confirmText={t('txt_delete')}
        cancelText={t('txt_cancel')}
        danger
        onConfirm={props.onConfirmDeletePasskey}
        onCancel={props.onCancelDeletePasskey}
      />
    </>
  );
}
