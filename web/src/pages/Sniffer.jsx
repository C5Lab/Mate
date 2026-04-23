import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { AttackMonitor } from '../components/AttackMonitor';
import { api } from '../api';
import { setState } from '../store';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';

const CLIENT_REFRESH_MS = 4000;

function ClientsTable({ aps }) {
  if (!aps.length) {
    return <div class="empty-state">No clients detected yet.</div>;
  }

  const sorted = [...aps].sort((a, b) => (b.clientCount || 0) - (a.clientCount || 0));

  return (
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>Network</th>
            <th>Channel</th>
            <th>Clients</th>
            <th>MACs</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((ap, idx) => (
            <tr key={`${ap.ssid}-${ap.channel}-${idx}`}>
              <td>{ap.ssid || 'Unknown'}</td>
              <td>CH{ap.channel}</td>
              <td>{ap.clientCount || 0}</td>
              <td>{ap.clients?.length ? ap.clients.join(', ') : '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Sniffer() {
  const [running, setRunning] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [packetCount, setPacketCount] = useState(0);
  const [aps, setAps] = useState([]);
  const refreshTimerRef = useRef(null);

  const apCount = aps.length;
  const clientTotal = aps.reduce((sum, ap) => sum + (ap.clientCount || 0), 0);

  useEffect(() => {
    (async () => {
      try {
        const status = await api.status();
        if (status?.ok && status.state === 'sniffer') {
          setRunning(true);
          await refreshClients();
          startRefreshLoop();
        } else {
          await loadSnifferResults();
        }
      } catch (e) {
        /* ignore initial sync errors */
      }
    })();

    const removeWs = wsAddListener((msg) => {
      if (msg.type === 'sniffer_count') {
        setPacketCount(msg.count || 0);
        setState({ packetCount: msg.count || 0 });
      }

      if (msg.type === 'sniffer_results_updated') {
        loadSnifferResults();
      }

      if (msg.type === 'attack_started' && msg.attack === 'sniffer') {
        setRunning(true);
      }

      if (msg.type === 'attack_stopped') {
        stopRefreshLoop();
        setRunning(false);
        setIsRefreshing(false);
      }
    });

    return () => {
      stopRefreshLoop();
      removeWs();
    };
  }, []);

  function stopRefreshLoop() {
    if (refreshTimerRef.current) {
      clearInterval(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }
  }

  async function loadSnifferResults() {
    try {
      const data = await api.snifferResults();
      if (!data.ok) return;
      setPacketCount(data.packetCount || 0);
      setAps(data.aps || []);
      setState({ packetCount: data.packetCount || 0 });
    } finally {
      setIsRefreshing(false);
    }
  }

  async function refreshClients() {
    setIsRefreshing(true);
    try {
      await api.refreshSniffer();
      await loadSnifferResults();
    } catch (e) {
      setIsRefreshing(false);
    }
  }

  function startRefreshLoop() {
    stopRefreshLoop();
    refreshTimerRef.current = setInterval(refreshClients, CLIENT_REFRESH_MS);
  }

  async function start() {
    stopRefreshLoop();
    setAps([]);
    setPacketCount(0);
    setIsRefreshing(false);

    const res = await api.sniffer();
    if (!res.ok) {
      showToast(res.error || 'Failed to start observer', 'error');
      return;
    }

    setRunning(true);
    await refreshClients();
    startRefreshLoop();
    showToast('Observer started', 'success');
  }

  async function stop() {
    stopRefreshLoop();
    await api.stop();
    setRunning(false);
    setIsRefreshing(false);
    showToast('Observer stopped', 'warning');
  }

  return (
    <Layout
      title="Network Observer"
      back="/"
    >
      <section class="glass-card card-body reveal">
        <div class="stats-grid" style="grid-template-columns: repeat(3, minmax(0, 1fr));">
          <article class="stat-card">
            <div class="stat-label">Packets</div>
            <div class="stat-value">{packetCount}</div>
          </article>
          <article class="stat-card">
            <div class="stat-label">APs</div>
            <div class="stat-value">{apCount}</div>
          </article>
          <article class="stat-card">
            <div class="stat-label">Clients</div>
            <div class="stat-value">{clientTotal}</div>
          </article>
        </div>

        <div class="btn-row">
          <button class="btn btn-success" onClick={start} disabled={running}>
            Start Observer
          </button>
          <button class="btn btn-secondary" onClick={refreshClients} disabled={!running || isRefreshing}>
            {isRefreshing ? <span class="spinner" /> : null}
            Refresh Clients
          </button>
          <button class="btn btn-danger" onClick={stop} disabled={!running}>
            Stop
          </button>
        </div>
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Observed Clients</h3>
          <span class={`badge ${running ? 'ok' : ''}`}>{running ? 'Live' : 'Idle'}</span>
        </div>
        <ClientsTable aps={aps} />
      </section>

      <AttackMonitor title="Observer Live Log" attackType="sniffer" />
    </Layout>
  );
}
