import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { AttackMonitor } from '../components/AttackMonitor';
import { api } from '../api';
import { setState } from '../store';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';

const REFRESH_INTERVAL_MS = 20000;

function ScanPreview({ networks }) {
  if (!networks.length) {
    return <div class="empty-state">Waiting for scan results...</div>;
  }

  return (
    <div class="network-scroll" style="max-height: 34vh;">
      {networks.map((network) => (
        <div class="network-row" key={network.index}>
          <div class="network-main">
            <div class="network-title">{network.ssid || '[Hidden]'}</div>
            <div class="network-meta">{network.bssid} | {network.security} | {network.band}</div>
          </div>
          <div class="signal-wrap">
            <div class="signal-value">CH{network.channel}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

function ObserverTable({ aps }) {
  if (!aps.length) {
    return <div class="empty-state">No AP/client snapshot available yet.</div>;
  }

  return (
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>Network</th>
            <th>Channel</th>
            <th>Clients</th>
            <th>Client MACs</th>
          </tr>
        </thead>
        <tbody>
          {aps.map((ap, index) => (
            <tr key={`${ap.ssid}-${ap.channel}-${index}`}>
              <td>{ap.ssid || 'Unknown'}</td>
              <td>CH{ap.channel}</td>
              <td>{ap.clientCount}</td>
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
  const [scanNetworks, setScanNetworks] = useState([]);
  const [scanComplete, setScanComplete] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [packetCount, setPacketCount] = useState(0);
  const [aps, setAps] = useState([]);
  const [hasSnapshot, setHasSnapshot] = useState(false);

  const refreshTimerRef = useRef(null);
  const scanPollRef = useRef(null);
  const scanTimeoutRef = useRef(null);

  useEffect(() => {
    const removeWs = wsAddListener((msg) => {
      if (msg.type === 'sniffer_count') {
        setPacketCount(msg.count || 0);
      }

      if (msg.type === 'sniffer_results_updated') {
        loadSnifferResults();
      }

      if (msg.type === 'attack_stopped') {
        stopTimers();
        setRunning(false);
        setIsRefreshing(false);
      }
    });

    return () => {
      stopTimers();
      removeWs();
    };
  }, []);

  function stopTimers() {
    if (refreshTimerRef.current) {
      clearInterval(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }
    if (scanPollRef.current) {
      clearInterval(scanPollRef.current);
      scanPollRef.current = null;
    }
    if (scanTimeoutRef.current) {
      clearTimeout(scanTimeoutRef.current);
      scanTimeoutRef.current = null;
    }
  }

  async function loadSnifferResults() {
    try {
      const data = await api.snifferResults();
      if (!data.ok) return;
      setPacketCount(data.packetCount || 0);
      setAps(data.aps || []);
      setHasSnapshot(Boolean(data.hasSnapshot));
      setState({ packetCount: data.packetCount || 0 });
    } finally {
      setIsRefreshing(false);
    }
  }

  async function refreshSnifferResults() {
    setIsRefreshing(true);
    try {
      const res = await api.refreshSniffer();
      if (!res.ok) {
        setIsRefreshing(false);
      }
    } catch (e) {
      setIsRefreshing(false);
    }
  }

  async function startSnifferAfterScan() {
    const res = await api.sniffer();
    if (!res.ok) {
      showToast(res.error || 'Failed to start observer', 'error');
      setIsScanning(false);
      return;
    }

    setRunning(true);
    setIsScanning(false);
    setPacketCount(0);
    setAps([]);
    setHasSnapshot(false);

    await refreshSnifferResults();
    refreshTimerRef.current = setInterval(refreshSnifferResults, REFRESH_INTERVAL_MS);
    showToast('Network Observer started', 'success');
  }

  async function start() {
    stopTimers();

    setRunning(false);
    setIsScanning(true);
    setIsRefreshing(false);
    setPacketCount(0);
    setAps([]);
    setHasSnapshot(false);
    setScanNetworks([]);
    setScanComplete(false);

    setState({ status: 'scanning', networks: [], selected: new Set() });

    try {
      const res = await api.scan();
      if (!res.ok) {
        setIsScanning(false);
        showToast(res.error || 'Scan failed', 'error');
        return;
      }
    } catch (e) {
      setIsScanning(false);
      showToast('Scan failed', 'error');
      return;
    }

    scanPollRef.current = setInterval(async () => {
      try {
        const data = await api.scanResults();
        if (!data.ok) return;

        setScanNetworks(data.networks || []);
        setState({ networks: data.networks || [], scanCount: data.count || 0 });

        if (data.complete) {
          stopTimers();
          setScanComplete(true);
          setState({ status: 'idle', lastScanAt: Date.now() });
          showToast(`Scan complete: ${data.count} APs`, 'success');
          await startSnifferAfterScan();
        }
      } catch (e) {
        /* ignore and keep polling */
      }
    }, 1800);

    scanTimeoutRef.current = setTimeout(() => {
      stopTimers();
      setIsScanning(false);
      setState({ status: 'idle' });
      showToast('Scan timed out', 'warning');
    }, 70000);
  }

  async function stop() {
    stopTimers();
    await api.stop();
    setRunning(false);
    setIsScanning(false);
    setIsRefreshing(false);
    showToast('Observer stopped', 'warning');
  }

  return (
    <Layout
      title="Network Observer"
      subtitle="One-tap flow: scan first, then monitor packet/client telemetry continuously."
      back="/"
    >
      <section class="glass-card card-body reveal">
        <div class="stats-grid" style="grid-template-columns: repeat(3, minmax(0, 1fr));">
          <article class="stat-card">
            <div class="stat-label">Packets</div>
            <div class="stat-value">{packetCount}</div>
          </article>
          <article class="stat-card">
            <div class="stat-label">Scan APs</div>
            <div class="stat-value">{scanNetworks.length}</div>
          </article>
          <article class="stat-card">
            <div class="stat-label">Snapshot</div>
            <div class="stat-value">{hasSnapshot ? 'Ready' : 'Pending'}</div>
          </article>
        </div>

        <div class="btn-row">
          <button class="btn btn-success" onClick={start} disabled={running || isScanning}>
            {isScanning ? <span class="spinner" /> : null}
            {isScanning ? 'Scanning...' : 'Start Observer'}
          </button>
          <button class="btn btn-secondary" onClick={refreshSnifferResults} disabled={!running || isRefreshing}>
            {isRefreshing ? <span class="spinner" /> : null}
            Refresh Snapshot
          </button>
          <button class="btn btn-danger" onClick={stop} disabled={!running && !isScanning}>
            Stop
          </button>
        </div>
      </section>

      {(scanNetworks.length > 0 || isScanning || scanComplete) && (
        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">Scan Stage</h3>
            {scanComplete ? <span class="badge info">Complete</span> : null}
          </div>
          <ScanPreview networks={scanNetworks} />
        </section>
      )}

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Observed Clients</h3>
          {running && isRefreshing ? <span class="badge info">Refreshing</span> : null}
        </div>
        {hasSnapshot ? (
          <ObserverTable aps={aps} />
        ) : (
          <div class="empty-state">
            {running ? 'Waiting for first snapshot...' : 'Start observer to collect client telemetry.'}
          </div>
        )}
      </section>

      <AttackMonitor title="Observer Live Log" attackType="sniffer" />
    </Layout>
  );
}
