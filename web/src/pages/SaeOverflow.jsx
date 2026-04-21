import { useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { AttackMonitor } from '../components/AttackMonitor';
import { api } from '../api';
import { getState } from '../store';
import { showToast } from '../components/Toast';

export function SaeOverflow() {
  const [running, setRunning] = useState(false);
  const st = getState();

  const targetNet = st.networks.find(n => st.selected.has(n.index));

  async function start() {
    if (st.selected.size !== 1) {
      showToast('Select exactly 1 network for SAE overflow', 'warning');
      return;
    }
    await api.select(Array.from(st.selected));
    const res = await api.sae();
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
    <Layout title="SAE Overflow" back="/">
      <div style="margin-bottom:12px;font-size:13px;color:var(--muted)">
        Target: {targetNet ? `${targetNet.ssid} (${targetNet.security})` : 'none'}
      </div>

      {targetNet && !targetNet.security.includes('WPA3') && !targetNet.security.includes('SAE') && (
        <div style="margin-bottom:12px;padding:10px;background:rgba(244,67,54,.1);border:1px solid var(--red);border-radius:8px;font-size:12px;color:var(--red)">
          Warning: Target does not appear to be WPA3/SAE. Attack may not be effective.
        </div>
      )}

      <div class="btn-row" style="margin-top:0;margin-bottom:14px">
        {!running ? (
          <button class="btn btn-magenta" onClick={start}
                  disabled={st.selected.size !== 1}>
            {'\u{1F513}'} Start SAE Overflow
          </button>
        ) : (
          <button class="btn btn-red" onClick={stop}>
            {'\u{26D4}'} Stop
          </button>
        )}
      </div>

      <AttackMonitor title="SAE Monitor" attackType="sae" onEvent={(msg) => {
        if (msg.type === 'attack_stopped') setRunning(false);
      }} />
    </Layout>
  );
}
