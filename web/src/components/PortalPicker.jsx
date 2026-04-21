import { useState, useEffect, useRef } from 'preact/hooks';
import { api } from '../api';
import { wsAddListener } from '../ws';

export function PortalPicker({ onSelect }) {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState(0);
  const retryTimerRef = useRef(null);
  const retryCountRef = useRef(0);
  const filesRef = useRef([]);

  function clearRetryTimer() {
    if (retryTimerRef.current) {
      clearTimeout(retryTimerRef.current);
      retryTimerRef.current = null;
    }
  }

  function finishWithFiles(nextFiles) {
    clearRetryTimer();
    retryCountRef.current = 0;
    filesRef.current = nextFiles;
    setFiles(nextFiles);
    setLoading(false);
  }

  function scheduleRetry() {
    if (retryTimerRef.current || filesRef.current.length > 0 || retryCountRef.current >= 5) {
      return;
    }

    retryCountRef.current += 1;
    retryTimerRef.current = setTimeout(() => {
      retryTimerRef.current = null;
      if (filesRef.current.length === 0) {
        loadPortals();
      }
    }, 1500);
  }

  useEffect(() => {
    let mounted = true;

    const removeWs = wsAddListener((msg) => {
      if (!mounted || msg.type !== 'portals' || !msg.files) return;
      finishWithFiles(msg.files);
    });

    loadPortals();

    return () => {
      mounted = false;
      clearRetryTimer();
      removeWs();
    };
  }, []);

  async function loadPortals() {
    setLoading(true);
    try {
      const data = await api.portals();
      if (data.files) {
        finishWithFiles(data.files);
        return;
      }

      if (data.status === 'loading') {
        scheduleRetry();
        return;
      }

      if (data.error === 'busy' || !data.ok) {
        scheduleRetry();
        return;
      }
    } catch (e) {
      console.error('Failed to load portals:', e);
      scheduleRetry();
      return;
    }

    setLoading(false);
  }

  async function handleSelect(idx) {
    setSelected(idx);
    await api.selectPortal(idx);
    if (onSelect) onSelect(idx);
  }

  if (loading) return <div class="empty-msg"><span class="spinner" /> Loading portals...</div>;

  return (
    <div class="field">
      <label>HTML Portal Template</label>
      <select
        value={selected}
        disabled={loading}
        onChange={e => handleSelect(parseInt(e.target.value))}
      >
        <option value={0}>-- Select portal --</option>
        {files.map(f => (
          <option key={f.index} value={f.index}>{f.name}</option>
        ))}
      </select>
      {files.length === 0 && (
        <div style="font-size:11px;color:var(--muted);margin-top:4px">
          No HTML files on SD card.
        </div>
      )}
    </div>
  );
}
