import { useEffect, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { api } from '../api';
import { getState } from '../store';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';
import { AttackMonitor } from '../components/AttackMonitor';

export function Deauth() {
  const [running, setRunning] = useState(false);
  const st = getState();

  useEffect(() => wsAddListener((msg) => {
    if (msg.type === 'attack_started' && msg.attack === 'deauth') setRunning(true);
    if (msg.type === 'attack_stopped') setRunning(false);
  }), []);

  async function start() {
    if (!st.selected.size) {
      showToast('Select targets in WiFi Scan first', 'warning');
      return;
    }

    await api.select(Array.from(st.selected));
    const res = await api.deauth();
    if (res.ok) {
      setRunning(true);
      showToast('Deauth started', 'success');
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
      title="Deauth Attack"
      subtitle="High-impact disruption. Use only with explicit authorization in a legal test environment."
      back="/"
    >
      <section class="glass-card card-body reveal">
        <div class="kv">
          <div class="kv-row">
            <span class="kv-key">Selected targets</span>
            <span class="kv-val">{st.selected.size}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">Mode</span>
            <span class="kv-val">Targeted deauthentication</span>
          </div>
        </div>
        <div class="btn-row">
          {!running ? (
            <button class="btn btn-danger" onClick={start} disabled={!st.selected.size}>
              Start Deauth
            </button>
          ) : (
            <button class="btn btn-danger" onClick={stop}>
              Stop Attack
            </button>
          )}
        </div>
      </section>

      <AttackMonitor title="Serial" attackType="deauth" />
    </Layout>
  );
}
