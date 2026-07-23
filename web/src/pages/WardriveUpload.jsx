import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { getState } from '../store';
import { api } from '../api';
import { showToast } from '../components/Toast';

function statusBadgeClass(status) {
  if (status === 'done' || status === 'ok') return 'ok';
  if (status === 'failed' || status === 'rate_limited' || status === 'pending') return 'warn';
  return 'info';
}

function humanSize(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

const ERROR_TEXT = {
  no_credentials: 'API key missing on device. Add it to /sdcard/lab/wigle.txt (or wdgwars.txt) and reboot the C5.',
  auth_failed: 'Authentication failed - check the API key on the device.',
  wifi: 'WiFi disconnected during upload. Reconnect and retry.',
  unsupported: 'This firmware does not support the upload command.',
  wifi_required: 'Connect the device to WiFi before uploading.',
};

export function WardriveUpload() {
  const st = getState();
  const [provider, setProvider] = useState('wigle');
  const [files, setFiles] = useState([]);
  const [filesLoading, setFilesLoading] = useState(true);
  const [ssid, setSsid] = useState('');
  const [password, setPassword] = useState('');
  const [connecting, setConnecting] = useState(false);
  const pollRef = useRef(null);

  async function loadFiles() {
    setFilesLoading(true);
    try {
      const data = await api.wardriveFiles();
      if (data && Array.isArray(data.files)) {
        setFiles(data.files);
        setFilesLoading(false);
        return true;
      }
    } catch (e) {
      /* keep polling */
    }
    return false;
  }

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const done = await loadFiles();
      if (!done && !cancelled) {
        pollRef.current = setInterval(async () => {
          const ok = await loadFiles();
          if (ok && pollRef.current) {
            clearInterval(pollRef.current);
            pollRef.current = null;
          }
        }, 1800);
      }
    })();
    return () => {
      cancelled = true;
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  /* Refresh the file list once an upload finishes so statuses update. */
  const prevRunning = useRef(false);
  useEffect(() => {
    if (prevRunning.current && !st.wardriveUploadRunning) {
      loadFiles();
    }
    prevRunning.current = st.wardriveUploadRunning;
  }, [st.wardriveUploadRunning]);

  async function connect() {
    if (!ssid.trim()) {
      showToast('Enter a WiFi SSID', 'warning');
      return;
    }
    setConnecting(true);
    try {
      const res = await api.wifiConnect(ssid.trim(), password);
      if (res && res.ok) showToast('Connecting to WiFi...', 'info');
      else showToast(res && res.error ? res.error : 'Connect rejected', 'error');
    } catch (e) {
      showToast('Failed to connect', 'error');
    } finally {
      setConnecting(false);
    }
  }

  async function disconnect() {
    try {
      await api.wifiDisconnect();
      showToast('Disconnecting WiFi', 'info');
    } catch (e) {
      showToast('Failed to disconnect', 'error');
    }
  }

  async function upload(mode, filename) {
    if (!st.staConnected) {
      showToast('Connect to WiFi first', 'warning');
      return;
    }
    try {
      const res = await api.wardriveUpload(provider, mode, filename);
      if (res && res.ok) {
        showToast(`Uploading to ${provider === 'wdgwars' ? 'WDGWars' : 'WiGLE'}...`, 'info');
      } else {
        const reason = res && res.error ? ERROR_TEXT[res.error] || res.error : 'Upload rejected';
        showToast(reason, 'error');
      }
    } catch (e) {
      showToast('Failed to start upload', 'error');
    }
  }

  const running = st.wardriveUploadRunning;
  const uploadsDisabled = !st.staConnected || running;
  const providerLabel = provider === 'wdgwars' ? 'WDGWars' : 'WiGLE';
  const result = st.wardriveUploadResult;
  const error = st.wardriveUploadError;

  return (
    <Layout
      title="Wardrive Upload"
      subtitle="Connect to WiFi, then push wardrive logs to WiGLE or WDGWars."
      back="/wardrive"
    >
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">1. WiFi</h3>
          <span class={`badge ${st.staConnected ? 'ok' : 'warn'}`}>
            {st.staConnected ? st.staSsid || 'Connected' : 'Not connected'}
          </span>
        </div>

        {st.staConnected ? (
          <div class="btn-row">
            <span class="section-note">
              Device joined {st.staSsid || 'a network'} - ready to upload.
            </span>
            <button class="btn btn-secondary" onClick={disconnect}>Disconnect</button>
          </div>
        ) : (
          <div>
            <div class="grid-two">
              <div class="field">
                <label class="field-label">SSID</label>
                <input class="input" value={ssid} onInput={(e) => setSsid(e.target.value)} />
              </div>
              <div class="field">
                <label class="field-label">Password</label>
                <input
                  class="input"
                  type="password"
                  value={password}
                  onInput={(e) => setPassword(e.target.value)}
                />
              </div>
            </div>
            <div class="btn-row">
              <button class="btn btn-primary" onClick={connect} disabled={connecting}>
                {connecting ? 'Connecting...' : 'Connect'}
              </button>
            </div>
          </div>
        )}
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">2. Provider</h3>
        </div>
        <div class="btn-row">
          <button
            class={`btn ${provider === 'wigle' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setProvider('wigle')}
          >
            WiGLE
          </button>
          <button
            class={`btn ${provider === 'wdgwars' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setProvider('wdgwars')}
          >
            WDGWars
          </button>
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" disabled={uploadsDisabled} onClick={() => upload('pending')}>
            Sync pending
          </button>
          <button class="btn btn-secondary" disabled={uploadsDisabled} onClick={() => upload('all')}>
            Force all
          </button>
        </div>
        {!st.staConnected ? (
          <span class="section-note">Connect to WiFi above to enable uploads.</span>
        ) : (
          <span class="section-note">Uploading to {providerLabel}. One upload runs at a time.</span>
        )}
      </section>

      {running || result || error ? (
        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">Progress</h3>
            <span class={`badge ${running ? 'info' : error ? 'warn' : 'ok'}`}>
              {running ? 'Uploading' : error ? 'Error' : 'Done'}
            </span>
          </div>
          {running ? (
            <div class="field">
              <label class="field-label">Live</label>
              <input class="input" value={st.wardriveUploadLast || 'Working...'} readOnly />
            </div>
          ) : null}
          {result ? (
            <span class="section-note">
              {result.provider === 'wdgwars' ? 'WDGWars' : 'WiGLE'} finished - uploaded {result.uploaded},
              skipped {result.skipped}, failed {result.failed}
              {result.rateLimited ? `, rate-limited ${result.rateLimited}` : ''}.
            </span>
          ) : null}
          {error ? (
            <span class="section-note">{ERROR_TEXT[error] || error}</span>
          ) : null}
        </section>
      ) : null}

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Wardrive files</h3>
          <button class="btn btn-secondary" onClick={loadFiles}>Refresh</button>
        </div>

        {filesLoading && !files.length ? (
          <div class="empty-state">Reading files from device...</div>
        ) : !files.length ? (
          <div class="empty-state">No wardrive files found.</div>
        ) : (
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>File</th>
                  <th>Rows</th>
                  <th>WiGLE</th>
                  <th>WDGWars</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {files.map((f) => (
                  <tr key={f.name}>
                    <td>
                      {f.name}
                      <div class="section-note">{humanSize(f.size)}</div>
                    </td>
                    <td>
                      W:{f.wifi} B:{f.ble} BT:{f.bt}
                    </td>
                    <td>
                      <span class={`badge ${statusBadgeClass(f.wigle)}`}>{f.wigle || 'unknown'}</span>
                    </td>
                    <td>
                      <span class={`badge ${statusBadgeClass(f.wdgwars)}`}>{f.wdgwars || 'unknown'}</span>
                    </td>
                    <td>
                      <button
                        class="btn btn-secondary"
                        disabled={uploadsDisabled}
                        onClick={() => upload('selected', f.name)}
                      >
                        Upload
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </Layout>
  );
}
