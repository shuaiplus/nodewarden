import { createPortal } from 'preact/compat';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import type { ComponentChildren } from 'preact';
import { TriangleAlert, X } from 'lucide-preact';
import { t } from '@/lib/i18n';

interface ConfirmDialogProps {
  open: boolean;
  title: ComponentChildren;
  message?: string;
  variant?: 'default' | 'warning';
  showIcon?: boolean;
  confirmText?: string;
  cancelText?: string;
  danger?: boolean;
  hideCancel?: boolean;
  hideConfirm?: boolean;
  closeButton?: boolean;
  confirmDisabled?: boolean;
  cancelDisabled?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children?: ComponentChildren;
  afterActions?: ComponentChildren;
}

function incrementDialogBodyLock() {
  if (typeof document === 'undefined') return;
  const body = document.body;
  const nextCount = Number(body.dataset.dialogCount || '0') + 1;
  body.dataset.dialogCount = String(nextCount);
  body.classList.add('dialog-open');
}

function decrementDialogBodyLock() {
  if (typeof document === 'undefined') return;
  const body = document.body;
  const nextCount = Math.max(0, Number(body.dataset.dialogCount || '0') - 1);
  if (nextCount === 0) {
    delete body.dataset.dialogCount;
    body.classList.remove('dialog-open');
    return;
  }
  body.dataset.dialogCount = String(nextCount);
}

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

let dialogIdCounter = 0;

function getFocusableElements(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter((element) => {
    if (element.hasAttribute('disabled') || element.getAttribute('aria-hidden') === 'true') return false;
    return !!(element.offsetWidth || element.offsetHeight || element.getClientRects().length);
  });
}

export function useDialogLifecycle(active: boolean, onCancel?: (() => void) | null) {
  useEffect(() => {
    if (!active) return;
    incrementDialogBodyLock();
    return () => decrementDialogBodyLock();
  }, [active]);

  useEffect(() => {
    if (!active || !onCancel || typeof window === 'undefined') return;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      onCancel();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [active, onCancel]);
}

export default function ConfirmDialog(props: ConfirmDialogProps) {
  const [present, setPresent] = useState(props.open);
  const [closing, setClosing] = useState(false);
  const cardRef = useRef<HTMLFormElement | null>(null);
  const maskPointerStartedRef = useRef(false);
  const restoreFocusRef = useRef<HTMLElement | null>(null);
  const lastTitleRef = useRef<ComponentChildren>(props.title);
  const dialogId = useMemo(() => `confirm-dialog-${++dialogIdCounter}`, []);
  const titleId = `${dialogId}-title`;
  const messageId = `${dialogId}-message`;
  const hasMessage = !!props.message;
  const canDismiss = !props.cancelDisabled && !closing;

  useEffect(() => {
    if (props.open) {
      lastTitleRef.current = props.title;
      setPresent(true);
      setClosing(false);
      return;
    }
    if (!present) return;
    setClosing(true);
    const timer = window.setTimeout(() => {
      setPresent(false);
      setClosing(false);
    }, 240);
    return () => window.clearTimeout(timer);
  }, [props.open, present]);

  useDialogLifecycle(present, canDismiss ? props.onCancel : null);

  useEffect(() => {
    if (!props.open || typeof document === 'undefined') return;
    const activeElement = document.activeElement;
    restoreFocusRef.current = activeElement instanceof HTMLElement ? activeElement : null;

    const frameId = window.requestAnimationFrame(() => {
      const card = cardRef.current;
      if (!card) return;
      const focusable = getFocusableElements(card);
      const firstField = focusable.find((element) => (
        element instanceof HTMLInputElement ||
        element instanceof HTMLSelectElement ||
        element instanceof HTMLTextAreaElement
      ));
      const cancelButton = focusable.find((element) => element.dataset.dialogCancel === 'true');
      const confirmButton = focusable.find((element) => element.dataset.dialogConfirm === 'true');
      const target = firstField || (props.danger ? cancelButton : confirmButton) || cancelButton || focusable[0] || card;
      target.focus({ preventScroll: true });
    });

    return () => window.cancelAnimationFrame(frameId);
  }, [props.open, props.danger]);

  useEffect(() => {
    if (props.open || present || typeof document === 'undefined') return;
    const target = restoreFocusRef.current;
    restoreFocusRef.current = null;
    if (!target || !document.contains(target)) return;
    target.focus({ preventScroll: true });
  }, [props.open, present]);

  useEffect(() => {
    return () => {
      const target = restoreFocusRef.current;
      if (!target || typeof document === 'undefined' || !document.contains(target)) return;
      target.focus({ preventScroll: true });
    };
  }, []);

  function handleDialogKeyDown(event: KeyboardEvent) {
    if (event.key !== 'Tab') return;
    const card = cardRef.current;
    if (!card) return;
    const focusable = getFocusableElements(card);
    if (focusable.length === 0) {
      event.preventDefault();
      card.focus({ preventScroll: true });
      return;
    }

    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const activeElement = document.activeElement;
    if (event.shiftKey) {
      if (activeElement === first || activeElement === card || !card.contains(activeElement)) {
        event.preventDefault();
        last.focus({ preventScroll: true });
      }
      return;
    }
    if (activeElement === last || activeElement === card || !card.contains(activeElement)) {
      event.preventDefault();
      first.focus({ preventScroll: true });
    }
  }

  if (!present || typeof document === 'undefined') return null;
  return createPortal((
    <div
      className={`dialog-mask ${props.variant === 'warning' ? 'warning' : ''} ${props.open && !closing ? 'open' : ''} ${closing ? 'closing' : ''}`}
      onPointerDown={(event) => {
        maskPointerStartedRef.current = event.target === event.currentTarget;
      }}
      onClick={(event) => {
        if (event.target !== event.currentTarget || !maskPointerStartedRef.current || !canDismiss) return;
        props.onCancel();
      }}
    >
      <form
        ref={cardRef}
        className={`dialog-card ${props.variant === 'warning' ? 'warning' : ''} ${props.open && !closing ? 'open' : ''} ${closing ? 'closing' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={hasMessage ? messageId : undefined}
        tabIndex={-1}
        onKeyDown={handleDialogKeyDown}
        onSubmit={(e) => {
          e.preventDefault();
          if (props.confirmDisabled || closing) return;
          props.onConfirm();
        }}
      >
        {props.variant === 'warning' ? (
          <>
            <div className="dialog-warning-strip" aria-hidden="true" />
            <div className="dialog-warning-head">
              <div className="dialog-warning-badge" aria-hidden="true">
                <TriangleAlert size={24} />
              </div>
              <div className="dialog-warning-kicker">{t('txt_warning')}</div>
            </div>
          </>
        ) : null}
        {props.closeButton && (
          <button
            type="button"
            className="dialog-close-btn"
            aria-label={t('txt_close')}
            disabled={props.cancelDisabled}
            onClick={() => {
              if (props.cancelDisabled) return;
              props.onCancel();
            }}
          >
            <X size={18} />
          </button>
        )}
        <h3 id={titleId} className="dialog-title">{props.open ? props.title : lastTitleRef.current}</h3>
        {hasMessage && <div id={messageId} className={`dialog-message ${props.variant === 'warning' ? 'warning' : ''}`}>{props.message}</div>}
        {props.children}
        {!props.hideConfirm && (
          <button
            type="submit"
            className={`btn ${props.danger ? 'btn-danger' : 'btn-primary'} dialog-btn`}
            disabled={props.confirmDisabled}
            data-dialog-confirm="true"
          >
            {props.confirmText || t('txt_yes')}
          </button>
        )}
        {!props.hideCancel && (
          <button
            type="button"
            className="btn btn-secondary dialog-btn"
            disabled={props.cancelDisabled}
            data-dialog-cancel="true"
            onClick={() => {
              if (props.cancelDisabled) return;
              props.onCancel();
            }}
          >
            {props.cancelText || t('txt_no')}
          </button>
        )}
        {props.afterActions}
      </form>
    </div>
  ), document.body);
}
