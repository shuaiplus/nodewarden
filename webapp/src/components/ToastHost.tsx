import type { ToastMessage } from '@/lib/types';

interface ToastHostProps {
  toasts: ToastMessage[];
  onClose: (id: string) => void;
}

export default function ToastHost({ toasts, onClose }: ToastHostProps) {
  if (!toasts.length) return null;
  return (
    <ul className="toast-stack">
      {toasts.map((toast) => (
        <li key={toast.id} className={`toast-item ${toast.type}`}>
          <div className="toast-text">{toast.text}</div>
          <button type="button" className="toast-close" onClick={() => onClose(toast.id)} aria-label="关闭通知">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
              <path d="M3 3l8 8M11 3l-8 8" />
            </svg>
          </button>
          <div className="toast-progress" />
        </li>
      ))}
    </ul>
  );
}
