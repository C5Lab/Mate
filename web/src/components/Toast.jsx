import { useState, useEffect } from 'preact/hooks';

let _show = null;

export function showToast(msg, type = 'info') {
  if (_show) _show(msg, type);
}

export function ToastContainer() {
  const [toast, setToast] = useState(null);

  useEffect(() => {
    _show = (msg, type) => {
      setToast({ msg, type });
      setTimeout(() => setToast(null), 3000);
    };
    return () => { _show = null; };
  }, []);

  if (!toast) return null;

  const colors = {
    info: 'var(--cyan)',
    success: 'var(--green)',
    error: 'var(--red)',
    warning: 'var(--yellow)',
  };

  return (
    <div style={{
      position: 'fixed', bottom: '20px', left: '50%', transform: 'translateX(-50%)',
      background: 'var(--panel)', border: `1px solid ${colors[toast.type] || colors.info}`,
      borderRadius: '10px', padding: '10px 20px', zIndex: 1000,
      fontSize: '13px', fontWeight: 600, color: colors[toast.type] || colors.info,
      boxShadow: '0 4px 20px rgba(0,0,0,.5)',
    }}>
      {toast.msg}
    </div>
  );
}
