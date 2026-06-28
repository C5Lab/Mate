import { useEffect, useState } from 'preact/hooks';

let _show = null;

export function showToast(msg, type = 'info') {
  if (_show) _show(msg, type);
}

export function ToastContainer() {
  const [toast, setToast] = useState(null);

  useEffect(() => {
    _show = (msg, type) => {
      setToast({ msg, type });
      setTimeout(() => setToast(null), 2600);
    };
    return () => {
      _show = null;
    };
  }, []);

  if (!toast) return null;

  return (
    <div class="toast-wrap">
      <div class={`toast toast-${toast.type || 'info'}`}>{toast.msg}</div>
    </div>
  );
}
