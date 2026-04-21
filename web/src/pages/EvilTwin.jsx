import { useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { AttackMonitor } from '../components/AttackMonitor';
import { PortalPicker } from '../components/PortalPicker';
import { api } from '../api';
import { getState } from '../store';
import { showToast } from '../components/Toast';

export function EvilTwin() {
  const [running, setRunning] = useState(false);
  const [portalSelected, setPortalSelected] = useState(false);
  const [passwords, setPasswords] = useState([]);
  const st = getState();

  const targetNet = st.networks.find(n => st.selected.has(n.index));

  async function start() {
    if (st.selected.size === 0) {
      showToast('Select networks first (first = clone target)', 'warning');
      return;
    }
    if (!portalSelected) {
      showToast('Select a portal HTML template', 'warning');
      return;
    }
    await api.select(Array.from(st.selected));
    const res = await api.evilTwin();
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

  function onEvent(msg) {
    if (msg.type === 'attack_stopped') setRunning(false);
    if (msg.type === 'password_received') {
      setPasswords(prev => [...prev, msg.password]);
    }
  }

  return (
    <Layout title="Evil Twin" back="/">
      <div style="margin-bottom:12px;font-size:13px;color:var(--muted)">
        Clone target: {targetNet ? targetNet.ssid : 'none'} |
        Deauth targets: {st.selected.size}
      </div>

      {!running && (
        <PortalPicker onSelect={() => setPortalSelected(true)} />
      )}

      <div class="btn-row" style="margin-bottom:14px">
        {!running ? (
          <button class="btn btn-orange" onClick={start}
                  disabled={st.selected.size === 0 || !portalSelected}>
            {'\u{1F47B}'} Start Evil Twin
          </button>
        ) : (
          <button class="btn btn-red" onClick={stop}>
            {'\u{26D4}'} Stop
          </button>
        )}
      </div>

      {passwords.length > 0 && (
        <div class="panel">
          <div class="panel-header">Captured Passwords ({passwords.length})</div>
          <div class="panel-body" style="padding:8px 14px">
            {passwords.map((pw, i) => (
              <div key={i} style="font-family:monospace;font-size:13px;padding:4px 0;color:var(--green)">
                {pw}
              </div>
            ))}
          </div>
        </div>
      )}

      <AttackMonitor title="Evil Twin Monitor" attackType="eviltwin" onEvent={onEvent} />
    </Layout>
  );
}
