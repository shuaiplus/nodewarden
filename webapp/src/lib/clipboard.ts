import { dispatchAppNotify } from '@/lib/app-notify';
import { t } from '@/lib/i18n';

interface CopyTextOptions {
  successMessage?: string;
  errorMessage?: string;
  emptyMessage?: string;
  notify?: boolean;
  onSuccess?: () => void;
  onError?: () => void;
}

/**
 * Fallback for older browsers or non-secure contexts where navigator.clipboard is not available.
 */
function fallbackCopyTextToClipboard(text: string): boolean {
  const textArea = document.createElement('textarea');
  textArea.value = text;

  // Ensure the textarea is not visible but part of the DOM
  textArea.style.position = 'fixed';
  textArea.style.left = '-9999px';
  textArea.style.top = '0';
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();

  let successful = false;
  try {
    successful = document.execCommand('copy');
  } catch (err) {
    successful = false;
  }

  document.body.removeChild(textArea);
  return successful;
}

export async function copyTextToClipboard(value: string, options: CopyTextOptions = {}): Promise<boolean> {
  const text = String(value || '');
  if (!text.trim()) {
    if (options.notify !== false) {
      dispatchAppNotify('warning', options.emptyMessage || t('txt_nothing_to_copy'));
    }
    return false;
  }

  let successful = false;

  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      successful = true;
    } else {
      successful = fallbackCopyTextToClipboard(text);
    }
  } catch (err) {
    // If clipboard API fails, try fallback
    try {
      successful = fallbackCopyTextToClipboard(text);
    } catch (fallbackErr) {
      successful = false;
    }
  }

  if (successful) {
    options.onSuccess?.();
    if (options.notify !== false) {
      dispatchAppNotify('success', options.successMessage || t('txt_copied'));
    }
    return true;
  } else {
    options.onError?.();
    if (options.notify !== false) {
      dispatchAppNotify('error', options.errorMessage || t('txt_copy_failed'));
    }
    return false;
  }
}
