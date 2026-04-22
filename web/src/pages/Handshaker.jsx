import { useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { AttackMonitor } from '../components/AttackMonitor';
import { api } from '../api';
import { getState } from '../store';
import { showToast } from '../components/Toast';

export function Handshaker() {
  const [running, setRunning] = useState(false);
  const [captures, setCaptures] = useState([]);
  const st = getState();

  async function start() {
    if (st.selected.size > 0) {
      await api.select(Array.from(st.selected));
    }

    const res = await api.handshake();
    if (res.ok) {
      setRunning(true);
      showToast('Handshaker started', 'success');
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
      title="Handshake Capture"
      subtitle="Capture WPA handshake data from selected targets or wide mode if no target is selected."
      back="/"
    >
      <section class="glass-card card-body reveal">
        <div class="kv">
          <div class="kv-row">
            <span class="kv-key">Target mode</span>
            <span class="kv-val">
              {st.selected.size ? `${st.selected.size} selected network(s)` : 'Global discovery mode'}
            </span>
          </div>
          <div class="kv-row">
            <span class="kv-key">Captured files</span>
            <span class="kv-val">{captures.length}</span>
          </div>
        </div>
        <div class="btn-row">
          {!running ? (
            <button class="btn btn-success" onClick={start}>
              Start Handshaker
            </button>
          ) : (
            <button class="btn btn-danger" onClick={stop}>
              Stop Handshaker
            </button>
          )}
        </div>
      </section>

      {captures.length ? (
        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">Capture Results</h3>
            <span class="badge ok">{captures.length}</span>
          </div>
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>SSID</th>
                  <th>Time</th>
                  <th>File</th>
                </tr>
              </thead>
              <tbody>
                {captures.map((capture, idx) => (
                  <tr key={`${capture.file}-${idx}`}>
                    <td>{capture.ssid || 'Unknown'}</td>
                    <td>{capture.ts}</td>
                    <td>{capture.file || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      <AttackMonitor
        title="Handshaker Telemetry"
        attackType="handshake"
        onEvent={(msg) => {
          if (msg.type === 'attack_stopped') setRunning(false);
          if (msg.type === 'handshake_captured' || msg.type === 'handshake_saved' || msg.type === 'pcap_saved') {
            setCaptures((prev) => [
              ...prev,
              {
                ssid: msg.ssid || 'Unknown',
                file: msg.file || '',
                ts: new Date().toLocaleTimeString(),
              },
            ]);
          }
        }}
      />
    </Layout>
  );
}
