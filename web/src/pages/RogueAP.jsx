import { useState, useEffect } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { AttackMonitor } from '../components/AttackMonitor';
import { PortalPicker } from '../components/PortalPicker';
import { api } from '../api';
import { getState } from '../store';
import { showToast } from '../components/Toast';

export function RogueAP() {
  const [running, setRunning] = useState(false);
  const [ssid, setSsid] = useState('');
  const [password, setPassword] = useState('');
  const [portalSelected, setPortalSelected] = useState(false);
  const [knownPasswords, setKnownPasswords] = useState([]);
  const st = getState();

  useEffect(() => {
    loadPasswords();
    /* Pre-fill SSID from first selected network */
    const net = st.networks.find(n => st.selected.has(n.index));
    if (net) setSsid(net.ssid);
  }, []);

  async function loadPasswords() {
    try {
      const data = await api.passwords();
      if (data.passwords) {
        setKnownPasswords(data.passwords);
        /* Auto-fill if we know the password for the selected network */
        const net = st.networks.find(n => st.selected.has(n.index));
        if (net) {
          const known = data.passwords.find(
            p => p.ssid.toLowerCase() === net.ssid.toLowerCase()
          );
          if (known) {
            setPassword(known.password);
            showToast(`Password known for ${net.ssid}`, 'success');
          }
        }
      }
    } catch (e) {
      /* First call may trigger fetch; retry after delay */
      setTimeout(loadPasswords, 3000);
    }
  }

  async function start() {
    if (!ssid || ssid.length === 0) {
      showToast('Enter SSID', 'warning'); return;
    }
    if (!password || password.length < 8) {
      showToast('Password must be 8+ characters', 'warning'); return;
    }
    if (!portalSelected) {
      showToast('Select a portal HTML template', 'warning'); return;
    }

    if (st.selected.size > 0) {
      await api.select(Array.from(st.selected));
    }

    const res = await api.rogueAP(ssid, password);
    if (res.ok) {
      setRunning(true);
    } else {
      showToast(res.error || 'Failed', 'error');
    }
  }

  async function stop() {
    await api.stop();
    setRunning(false);
  }

  return (
    <Layout title="Rogue AP" back="/">
      {!running && (
        <>
          <div class="field">
            <label>AP SSID</label>
            <input type="text" value={ssid} maxLength={32}
                   onInput={e => setSsid(e.target.value)}
                   placeholder="Network name" />
          </div>

          <div class="field">
            <label>
              WPA2 Password
              {knownPasswords.length > 0 && (
                <span class="badge badge-green" style="margin-left:8px">
                  {knownPasswords.length} known
                </span>
              )}
            </label>
            <input type="text" value={password}
                   onInput={e => setPassword(e.target.value)}
                   placeholder="Min 8 characters" />
          </div>

          <PortalPicker onSelect={() => setPortalSelected(true)} />
        </>
      )}

      <div class="btn-row" style="margin-bottom:14px">
        {!running ? (
          <button class="btn btn-magenta" onClick={start}>
            {'\u{1F3AD}'} Start Rogue AP
          </button>
        ) : (
          <button class="btn btn-red" onClick={stop}>
            {'\u{26D4}'} Stop
          </button>
        )}
      </div>

      <AttackMonitor title="Rogue AP Monitor" attackType="rogueap" onEvent={(msg) => {
        if (msg.type === 'attack_stopped') setRunning(false);
      }} />
    </Layout>
  );
}
