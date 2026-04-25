import { useEffect, useState } from 'preact/hooks';
import { Layout } from '../../components/Layout';
import { api } from '../../api';
import { showToast } from '../../components/Toast';
import { wsAddListener } from '../../ws';

const PRESETS = [315, 433.92, 868, 915];

export function SubGhzJammer() {
  const [freq, setFreq] = useState('433.92');
  const [running, setRunning] = useState(false);

  useEffect(() => wsAddListener((msg) => {
    if (msg.type === 'attack_stopped') setRunning(false);
  }), []);

  async function start() {
    const f = parseFloat(freq);
    if (!isFinite(f) || f <= 0) {
      showToast('Invalid frequency', 'warning');
      return;
    }
    const res = await api.subghzJam(f);
    if (res.ok) {
      setRunning(true);
      showToast(`Jamming ${f.toFixed(2)} MHz`, 'warning');
    } else {
      showToast(res.error || 'Jammer failed', 'error');
    }
  }

  async function stop() {
    await api.stop();
    setRunning(false);
  }

  return (
    <Layout title="SubGHZ Jammer" back="/subghz">
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Continuous TX</h3>
          <span class={`badge ${running ? 'warn' : ''}`}>{running ? 'JAMMING' : 'idle'}</span>
        </div>

        <div class="field">
          <label class="field-label">Frequency (MHz)</label>
          <input
            class="input"
            type="number"
            step="0.01"
            min="300"
            max="928"
            value={freq}
            disabled={running}
            onInput={(e) => setFreq(e.currentTarget.value)}
          />
        </div>

        <div class="btn-row">
          {PRESETS.map((p) => (
            <button
              key={p}
              class="btn btn-soft"
              onClick={() => setFreq(String(p))}
              disabled={running}
            >
              {p.toFixed(2)}
            </button>
          ))}
        </div>

        <div class="btn-row">
          {!running ? (
            <button class="btn btn-danger btn-block" onClick={start}>Start Jammer</button>
          ) : (
            <button class="btn btn-soft btn-block" onClick={stop}>Stop Jammer</button>
          )}
        </div>
      </section>
    </Layout>
  );
}
