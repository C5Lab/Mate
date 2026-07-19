import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { api } from '../api';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';

export function SnifferDog() {
  const [running, setRunning] = useState(false);
  const [starting, setStarting] = useState(false);
  const [count, setCount] = useState(0);
  const [events, setEvents] = useState([]);
  const startedRef = useRef(false);

  useEffect(() => {
    const removeWs = wsAddListener((msg) => {
      if (msg.type === 'attack_started' && msg.attack === 'sniffer_dog') setRunning(true);
      if (msg.type === 'attack_stopped') setRunning(false);
      // The counter/events are refreshed from the device-cached REST poll
      // below (source of truth) so they keep updating even if the send-only
      // WS is dropped.
    });

    // Poll device-side sniffer-dog results every 2s.
    let alive = true;
    async function pollResults() {
      try {
        const res = await api.snifferDogResults();
        if (!alive || !res || !res.ok) return;
        setCount(res.count || 0);
        const list = (res.events || []).map((e, i) => ({
          id: `${e.at}-${e.n}-${i}`,
          n: e.n, ap: e.ap, sta: e.sta, ch: e.ch, rssi: e.rssi,
        })).reverse().slice(0, 200);
        setEvents(list);
      } catch (_) { /* ignore */ }
    }
    pollResults();
    const resTimer = setInterval(pollResults, 2000);

    (async () => {
      if (startedRef.current) return;
      startedRef.current = true;
      setStarting(true);
      try {
        await api.stop();
        const res = await api.snifferDog();
        if (res.ok) {
          setRunning(true);
          showToast('Sniffer Dog started', 'success');
        } else {
          showToast(res.error || 'Failed to start Sniffer Dog', 'error');
        }
      } catch (e) {
        showToast('Failed to start Sniffer Dog', 'error');
      } finally {
        setStarting(false);
      }
    })();

    return () => { alive = false; clearInterval(resTimer); removeWs(); };
  }, []);

  async function start() {
    setStarting(true);
    try {
      await api.stop();
      const res = await api.snifferDog();
      if (res.ok) {
        setRunning(true);
        setEvents([]);
        setCount(0);
        showToast('Sniffer Dog started', 'success');
      } else {
        showToast(res.error || 'Failed to start Sniffer Dog', 'error');
      }
    } finally {
      setStarting(false);
    }
  }

  async function stop() {
    await api.stop();
    setRunning(false);
    showToast('Sniffer Dog stopped', 'warning');
  }

  return (
    <Layout
      title="Sniffer Dog"
      subtitle="Captures AP-STA pairs and immediately fires targeted deauth at each client."
      back="/global"
    >
      <section class="glass-card card-body reveal">
        <div class="stats-grid" style="grid-template-columns: repeat(2, minmax(0, 1fr));">
          <article class="stat-card">
            <div class="stat-label">Deauths sent</div>
            <div class="stat-value">{count}</div>
          </article>
          <article class="stat-card">
            <div class="stat-label">Status</div>
            <div class="stat-value">{starting ? 'Starting...' : running ? 'Running' : 'Idle'}</div>
          </article>
        </div>

        <div class="btn-row">
          {!running ? (
            <button class="btn btn-primary" onClick={start} disabled={starting}>
              {starting ? <><span class="spinner" /> Starting...</> : 'Start Sniffer Dog'}
            </button>
          ) : (
            <button class="btn btn-danger" onClick={stop}>
              Stop Sniffer Dog
            </button>
          )}
        </div>
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Deauth Activity</h3>
          <span class={`badge ${running ? 'ok' : ''}`}>{running ? 'Live' : 'Idle'}</span>
        </div>
        {events.length > 0 ? (
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr><th>#</th><th>AP</th><th>STA</th><th>CH</th><th>RSSI</th></tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id}>
                    <td>{e.n}</td>
                    <td>{e.ap}</td>
                    <td>{e.sta}</td>
                    <td>{e.ch}</td>
                    <td>{e.rssi}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div class="empty-state">Waiting for AP-STA pairs...</div>
        )}
      </section>
    </Layout>
  );
}
