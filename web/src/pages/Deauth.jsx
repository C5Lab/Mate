import { useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { AttackMonitor } from '../components/AttackMonitor';
import { api } from '../api';
import { getState } from '../store';
import { showToast } from '../components/Toast';

export function Deauth() {
  const [running, setRunning] = useState(false);
  const st = getState();

  async function start() {
    if (st.selected.size === 0) {
      showToast('Select networks first', 'warning');
      return;
    }
    await api.select(Array.from(st.selected));
    const res = await api.deauth();
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
    <Layout title="Deauth Attack" back="/">
      <div style="margin-bottom:12px;font-size:13px;color:var(--muted)">
        Targets: {st.selected.size} network(s) selected
      </div>

      <div class="btn-row" style="margin-top:0;margin-bottom:14px">
        {!running ? (
          <button class="btn btn-red" onClick={start} disabled={st.selected.size === 0}>
            {'\u{1F4A5}'} Start Deauth
          </button>
        ) : (
          <button class="btn btn-red" onClick={stop}>
            {'\u{26D4}'} Stop
          </button>
        )}
      </div>

      <AttackMonitor title="Deauth Monitor" attackType="deauth" onEvent={(msg) => {
        if (msg.type === 'attack_stopped') setRunning(false);
      }} />
    </Layout>
  );
}
