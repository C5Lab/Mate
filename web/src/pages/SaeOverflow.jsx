import { useEffect, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { api } from '../api';
import { getState } from '../store';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';
import { AttackMonitor } from '../components/AttackMonitor';

export function SaeOverflow() {
  const [running, setRunning] = useState(false);
  const st = getState();
  const target = st.networks.find((n) => st.selected.has(n.index));

  useEffect(() => wsAddListener((msg) => {
    if (msg.type === 'attack_started' && msg.attack === 'sae') setRunning(true);
    if (msg.type === 'attack_stopped') setRunning(false);
  }), []);

  async function start() {
    if (st.selected.size !== 1) {
      showToast('Select exactly one WPA3 target', 'warning');
      return;
    }

    await api.select(Array.from(st.selected));
    const res = await api.sae();
    if (res.ok) {
      setRunning(true);
      showToast('SAE Overflow started', 'success');
    } else {
      showToast(res.error || 'Failed to start', 'error');
    }
  }

  async function stop() {
    await api.stop();
    setRunning(false);
    showToast('Stopped', 'warning');
  }

  const likelyIncompatible =
    target && !target.security.includes('WPA3') && !target.security.includes('SAE');

  return (
    <Layout
      title="SAE Overflow"
      subtitle="Single-target WPA3/SAE test flow with strict target validation."
      back="/"
    >
      <section class="glass-card card-body reveal">
        <div class="kv">
          <div class="kv-row">
            <span class="kv-key">Target</span>
            <span class="kv-val">{target ? `${target.ssid}${target.vendor ? ` · ${target.vendor}` : ''} (${target.security})` : 'Not selected'}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">Selected count</span>
            <span class="kv-val">{st.selected.size}</span>
          </div>
        </div>

        {likelyIncompatible ? (
          <div class="alert warn">Target does not look like WPA3/SAE. Expected effectiveness is low.</div>
        ) : null}

        <div class="btn-row">
          {!running ? (
            <button class="btn btn-primary" onClick={start} disabled={st.selected.size !== 1}>
              Start SAE Overflow
            </button>
          ) : (
            <button class="btn btn-danger" onClick={stop}>
              Stop SAE Overflow
            </button>
          )}
        </div>
      </section>

      <AttackMonitor title="Serial" attackType="sae" />
    </Layout>
  );
}
