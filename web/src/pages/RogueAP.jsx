import { useEffect, useState } from 'preact/hooks';
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
    const selected = st.networks.find((n) => st.selected.has(n.index));
    if (selected?.ssid) setSsid(selected.ssid);
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

      <AttackMonitor
        title="Rogue AP Telemetry"
        attackType="rogueap"
        onEvent={(msg) => {
          if (msg.type === 'attack_stopped') setRunning(false);
        }}
      />
    </Layout>
  );
}
