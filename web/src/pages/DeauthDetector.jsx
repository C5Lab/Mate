import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { api } from '../api';
import { showToast } from '../components/Toast';

function ageLabel(ms) {
  if (ms < 1500) return 'now';
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s ago`;
  return `${Math.round(s / 60)}m ago`;
}

export function DeauthDetector() {
  const [running, setRunning] = useState(false);
  const [events, setEvents] = useState([]);
  const timerRef = useRef(null);

  // Poll the aggregated detections over HTTP (robust to WebSocket drops during
  // a deauth flood — the firmware keeps the authoritative per-AP cache).
  useEffect(() => {
    const load = async () => {
      try {
        const res = await api.deauthDetected();
        if (!res || !res.ok) return;
        setRunning(!!res.active);
        setEvents(Array.isArray(res.events) ? res.events : []);
      } catch (e) { /* ignore */ }
    };
    load();
    timerRef.current = setInterval(load, 2000);
    return () => clearInterval(timerRef.current);
  }, []);

  async function start() {
    const res = await api.deauthDetect();
    if (res && res.ok) {
      setRunning(true);
      setEvents([]);
      showToast('Deauth detector started', 'success');
    } else {
      showToast(res?.error === 'busy' ? 'Device busy' : 'Start failed', 'error');
    }
  }

  async function stop() {
    await api.stop();
    setRunning(false);
    showToast('Detector stopped', 'info');
  }

  const totalHits = events.reduce((sum, e) => sum + (e.hits || 0), 0);
  const sorted = [...events].sort((a, b) => (b.hits || 0) - (a.hits || 0));

  return (
    <Layout
      title="Deauth Detector"
      subtitle="Active watchdog: flags APs being hit with deauth/disassoc frames."
      back="/"
    >
      <section class="glass-card card-body reveal">
        <div class="stats-grid" style="grid-template-columns: repeat(3, minmax(0, 1fr));">
          <article class="stat-card">
            <div class="stat-label">Detector</div>
            <div class="stat-value">{running ? 'Running' : 'Stopped'}</div>
          </article>
          <article class="stat-card">
            <div class="stat-label">APs hit</div>
            <div class="stat-value">{events.length}</div>
          </article>
          <article class="stat-card">
            <div class="stat-label">Total frames</div>
            <div class="stat-value">{totalHits}</div>
          </article>
        </div>

        <div class="btn-row">
          <button class="btn btn-success" onClick={start} disabled={running}>
            Start
          </button>
          <button class="btn btn-danger" onClick={stop} disabled={!running}>
            Stop
          </button>
        </div>

        <div class="section-note">
          Runs <code>deauth_detector</code> on the C5 and polls results over HTTP,
          so counts stay complete even during a heavy deauth flood.
        </div>
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Detected APs</h3>
          <span class={`badge ${running ? 'ok' : 'info'}`}>
            {running ? 'Live' : 'Idle'}
          </span>
        </div>

        {!events.length ? (
          <div class="empty-state">
            {running ? 'Listening… no deauth frames seen yet.' : 'Start the detector to watch for deauth attacks.'}
          </div>
        ) : (
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>AP</th>
                  <th>BSSID</th>
                  <th>CH</th>
                  <th>RSSI</th>
                  <th>Frames</th>
                  <th>Last</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((e) => (
                  <tr key={e.bssid}>
                    <td>{e.ap || '[Hidden]'}</td>
                    <td>{e.bssid}</td>
                    <td>{e.ch}</td>
                    <td>{e.rssi}</td>
                    <td><span class="badge ok">{e.hits}</span></td>
                    <td>{ageLabel(e.age_ms || 0)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </Layout>
  );
}
