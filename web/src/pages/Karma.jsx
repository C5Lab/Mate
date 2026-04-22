import { useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { showToast } from '../components/Toast';

export function Karma() {
  const [running, setRunning] = useState(false);
  const [mode, setMode] = useState('aggressive');
  const [spoofSsid, setSpoofSsid] = useState('Free_WiFi');

  function startKarma() {
    setRunning(true);
    showToast('Karma command not available in current firmware API', 'warning');
    setTimeout(() => setRunning(false), 1200);
  }

  return (
    <Layout
      title="Karma"
      subtitle="Configure Karma behavior profile and spoof policy before deployment."
      back="/"
    >
      <section class="glass-card card-body reveal">
        <div class="field">
          <label class="field-label">Mode</label>
          <select class="select" value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="aggressive">Aggressive</option>
            <option value="balanced">Balanced</option>
            <option value="stealth">Stealth</option>
          </select>
        </div>

        <div class="field">
          <label class="field-label">Spoof SSID Profile</label>
          <input class="input" value={spoofSsid} onInput={(e) => setSpoofSsid(e.target.value)} />
        </div>

        <div class="btn-row">
          <button class="btn btn-primary" onClick={startKarma} disabled={running}>
            {running ? <span class="spinner" /> : null}
            {running ? 'Requesting...' : 'Start Karma'}
          </button>
          <button class="btn btn-secondary" onClick={() => setRunning(false)}>
            Stop
          </button>
        </div>
      </section>

      <div class="alert warn">
        Backend command endpoint for Karma is not yet exposed. This screen prepares UX and parameters for firmware integration.
      </div>
    </Layout>
  );
}
