import { useEffect, useRef, useState } from 'preact/hooks';
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
    if (retryTimerRef.current || filesRef.current.length > 0 || retryCountRef.current >= 6) {
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
    const removeWs = wsAddListener((msg) => {
      if (msg.type === 'portals' && msg.files) {
        finishWithFiles(msg.files);
      }
    });

    loadPortals();

    return () => {
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
      if (data.status === 'loading' || data.error === 'busy' || !data.ok) {
        scheduleRetry();
        return;
      }
    } catch (e) {
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

  return (
    <div class="field">
      <label class="field-label">
        Portal Template
        {files.length > 0 && <span class="badge info">{files.length} loaded</span>}
      </label>
      <select class="select" value={selected} disabled={loading} onChange={(e) => handleSelect(parseInt(e.target.value, 10))}>
        <option value={0}>Select HTML portal</option>
        {files.map((f) => (
          <option key={f.index} value={f.index}>
            {f.name}
          </option>
        ))}
      </select>
      {loading ? <div class="section-note">Fetching portal list from SD...</div> : null}
      {!loading && files.length === 0 ? <div class="section-note">No portal templates found on SD card.</div> : null}
    </div>
  );
}
