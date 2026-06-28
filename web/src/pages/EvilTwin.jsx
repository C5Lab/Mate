import { useEffect, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { PortalPicker } from '../components/PortalPicker';
import { api } from '../api';
import { getState } from '../store';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';

export function EvilTwin() {
  const [running, setRunning] = useState(false);
  const [portalSelected, setPortalSelected] = useState(false);
  const [passwords, setPasswords] = useState([]);
  const st = getState();

  useEffect(() => wsAddListener((msg) => {
    if (msg.type === 'attack_started' && msg.attack === 'eviltwin') setRunning(true);
    if (msg.type === 'attack_stopped') setRunning(false);
    if (msg.type === 'password_received') {
      setPasswords((prev) => [
        {
          id: `${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
          password: msg.password,
          time: new Date().toLocaleTimeString(),
        },
        ...prev,
      ]);
      showToast(`Password captured: ${msg.password}`, 'success');
    }
  }), []);

  const targetNet = st.networks.find((n) => st.selected.has(n.index));

  async function start() {
    if (!st.selected.size) {
      showToast('Choose at least one target network first', 'warning');
      return;
    }
    if (!portalSelected) {
      showToast('Select an SD portal template', 'warning');
      return;
    }

    await api.select(Array.from(st.selected));
    const res = await api.evilTwin();
    if (res.ok) {
      setRunning(true);
      showToast('Evil Twin started', 'success');
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
      title="Evil Twin"
      subtitle="Clone selected AP and present a credential portal template from SD storage."
      back="/"
    >
      <section class="glass-card card-body reveal">
        <div class="kv">
          <div class="kv-row">
            <span class="kv-key">Clone target</span>
            <span class="kv-val">{targetNet?.ssid || 'Not selected'}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">Deauth targets</span>
            <span class="kv-val">{st.selected.size}</span>
          </div>
        </div>

        {!running ? <PortalPicker onSelect={(idx) => setPortalSelected(idx > 0)} /> : null}

        <div class="btn-row">
          {!running ? (
            <button class="btn btn-primary" onClick={start} disabled={!st.selected.size || !portalSelected}>
              Start Evil Twin
            </button>
          ) : (
            <button class="btn btn-danger" onClick={stop}>
              Stop Operation
            </button>
          )}
        </div>
      </section>

      {passwords.length > 0 ? (
        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">Captured Credentials</h3>
            <span class="badge ok">{passwords.length}</span>
          </div>
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Password</th>
                </tr>
              </thead>
              <tbody>
                {passwords.map((pw) => (
                  <tr key={pw.id}>
                    <td>{pw.time}</td>
                    <td>{pw.password}</td>
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
