import { useEffect, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { PortalPicker } from '../components/PortalPicker';
import { api } from '../api';
import { getState } from '../store';
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

export function RogueAP() {
  const [running, setRunning] = useState(false);
  const [ssid, setSsid] = useState('');
  const [password, setPassword] = useState('');
  const [portalSelected, setPortalSelected] = useState(false);
  const [knownPasswords, setKnownPasswords] = useState([]);
  const [captured, setCaptured] = useState([]);
  const st = getState();
  const selectedNet = st.networks.find((n) => st.selected.has(n.index));

  useEffect(() => {
    loadPasswords();
    const selected = st.networks.find((n) => st.selected.has(n.index));
    if (selected?.ssid) setSsid(selected.ssid);
    const removeWs = wsAddListener((msg) => {
      if (msg.type === 'attack_started' && msg.attack === 'rogueap') setRunning(true);
      if (msg.type === 'attack_stopped') setRunning(false);
      // Credential list comes from the device-cached REST poll (source of
      // truth); the WS handlers below only fire an instant toast.
      if (msg.type === 'portal_data') {
        const fields = parseFormFields(msg.data);
        const summary = fields.map((f) => `${f.key}=${f.value}`).join('  ');
        showToast(`Credentials captured: ${summary}`, 'success');
      }
      if (msg.type === 'password_received') {
        showToast(`Password captured: ${msg.password}`, 'success');
      }
    });

    let alive = true;
    async function pollCaptures() {
      try {
        const res = await api.portalCaptures();
        if (!alive || !res || !res.ok) return;
        const list = (res.captures || []).map((c, i) => {
          const fields = parseFormFields(c.data);
          return {
            id: `${c.at}-${i}`,
            fields,
            summary: fields.map((f) => `${f.key}=${f.value}`).join('  ') || c.data,
          };
        }).reverse();
        setCaptured(list);
      } catch (_) { /* ignore */ }
    }
    pollCaptures();
    const capTimer = setInterval(pollCaptures, 2000);

    return () => { alive = false; clearInterval(capTimer); removeWs(); };
  }, []);

  async function loadPasswords() {
    try {
      const data = await api.passwords();
      if (data.passwords) {
        setKnownPasswords(data.passwords);

        const selected = st.networks.find((n) => st.selected.has(n.index));
        if (selected) {
          const known = data.passwords.find(
            (item) => item.ssid.toLowerCase() === selected.ssid.toLowerCase(),
          );
          if (known?.password) {
            setPassword(known.password);
            showToast(`Known password loaded for ${selected.ssid}`, 'success');
          }
        }
      }
    } catch (e) {
      setTimeout(loadPasswords, 2500);
    }
  }

  async function start() {
    if (!ssid.trim()) {
      showToast('SSID is required', 'warning');
      return;
    }
    if (password.length < 8) {
      showToast('Password must be at least 8 characters', 'warning');
      return;
    }
    if (!portalSelected) {
      showToast('Select a portal template', 'warning');
      return;
    }

    if (st.selected.size) {
      await api.select(Array.from(st.selected));
    }

    const res = await api.rogueAP(ssid.trim(), password);
    if (res.ok) {
      setRunning(true);
      showToast('Rogue AP started', 'success');
    } else {
      showToast(res.error || 'Failed to start', 'error');
    }
  }

  async function stop() {
    await api.stop();
    setRunning(false);
    showToast('Stopped', 'warning');
  }

  return (
    <Layout
      title="Rogue AP"
      subtitle="Deploy a standalone AP with chosen SSID, credentials, and portal template."
      back="/"
    >
      <section class="glass-card card-body reveal">
        {!running ? (
          <>
            <div class="field">
              <label class="field-label">AP SSID</label>
              <input
                class="input"
                type="text"
                maxLength={32}
                value={ssid}
                onInput={(e) => setSsid(e.target.value)}
                placeholder="Corporate Guest"
              />
              {selectedNet?.vendor ? <p class="module-note">{selectedNet.vendor}</p> : null}
            </div>

            <div class="field">
              <label class="field-label">
                WPA2 Password
                <span class="badge info">{knownPasswords.length} known</span>
              </label>
              <input
                class="input"
                type="text"
                value={password}
                onInput={(e) => setPassword(e.target.value)}
                placeholder="Minimum 8 chars"
              />
            </div>

            <PortalPicker onSelect={(idx) => setPortalSelected(idx > 0)} />
          </>
        ) : null}

        <div class="btn-row">
          {!running ? (
            <button class="btn btn-primary" onClick={start}>
              Start Rogue AP
            </button>
          ) : (
            <button class="btn btn-danger" onClick={stop}>
              Stop Rogue AP
            </button>
          )}
        </div>
      </section>

      {captured.length > 0 ? (
        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">Captured Credentials</h3>
            <span class="badge ok">{captured.length}</span>
          </div>
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>#</th><th>Submitted data</th></tr></thead>
              <tbody>
                {captured.map((c, i) => (
                  <tr key={c.id}>
                    <td>{captured.length - i}</td>
                    <td>
                      {(c.fields && c.fields.length) ? c.fields.map((f) => (
                        <div key={f.key}><span class="kv-key">{f.key}:</span> {f.value}</div>
                      )) : c.summary}
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
