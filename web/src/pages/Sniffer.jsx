import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { AttackMonitor } from '../components/AttackMonitor';
import { api } from '../api';
import { getState, setState } from '../store';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';

const REFRESH_INTERVAL_MS = 20000;

function ScanResultsPreview({ networks }) {
  if (!networks.length) {
    return <div class="empty-msg">Waiting for scan results...</div>;
  }

  return (
    <div class="observer-scan-list">
      {networks.map((network) => (
        <div class="observer-scan-row" key={network.index}>
          <div>
            <div class="observer-ssid">{network.ssid || '[Hidden]'}</div>
            <div class="observer-scan-meta">{network.bssid} | {network.security} | {network.band}</div>
          </div>
          <div class="observer-scan-side">CH{network.channel} | {network.rssi}</div>
        </div>
      ))}
    </div>
  );
}

function SnifferResultsTable({ aps }) {
  if (!aps.length) {
    return <div class="empty-msg">No APs with clients found.</div>;
  }

  return (
    <div class="observer-table-wrap">
      <table class="observer-table">
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
              <td>
                <div class="observer-ssid">{ap.ssid || 'Unknown SSID'}</div>
              </td>
              <td>CH{ap.channel}</td>
              <td>{ap.clientCount}</td>
              <td>
                <div class="observer-macs">
                  {ap.clients.length > 0 ? ap.clients.map((client) => (
                    <span class="observer-mac" key={`${ap.ssid}-${client}`}>{client}</span>
                  )) : <span class="observer-empty">Waiting for client list...</span>}
                </div>
              </td>
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
        setPacketCount(msg.count);
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
      setIsRefreshing(false);
    } catch (e) {
      console.error('Failed to load sniffer results:', e);
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
      console.error('Failed to refresh sniffer results:', e);
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
    setIsScanning(true);
    setRunning(false);
    setIsRefreshing(false);
    setPacketCount(0);
    setAps([]);
    setHasSnapshot(false);
    setScanNetworks([]);
    setScanComplete(false);
    setState({ networks: [], selected: new Set(), status: 'scanning' });

    try {
      const res = await api.scan();
      if (!res.ok) {
        showToast(res.error || 'Scan failed', 'error');
        setIsScanning(false);
        return;
      }
    } catch (e) {
      showToast('Scan failed', 'error');
      setIsScanning(false);
      return;
    }

    scanPollRef.current = setInterval(async () => {
      try {
        const data = await api.scanResults();
        if (!data.ok) return;

        setScanNetworks(data.networks || []);
        setState({ networks: data.networks || [], selected: new Set() });

        if (data.complete) {
          stopTimers();
          setScanComplete(true);
          showToast(`Scan complete: ${data.count} networks`, 'success');
          await startSnifferAfterScan();
        }
      } catch (e) {
        console.error('Failed to poll scan results:', e);
      }
    }, 2000);

    scanTimeoutRef.current = setTimeout(() => {
      stopTimers();
      setIsScanning(false);
      showToast('Scan timed out', 'warning');
    }, 60000);
  }

  async function stop() {
    stopTimers();
    await api.stop();
    setRunning(false);
    setIsScanning(false);
    setIsRefreshing(false);
  }

  return (
    <Layout title="Network Observer" back="/">
      <div class="observer-stats">
        <div class="observer-stat-label">Packages</div>
        <div class="observer-stat-value">{packetCount}</div>
      </div>

      <div class="btn-row" style="margin-top:0;margin-bottom:14px">
        <button class="btn btn-green" onClick={start} disabled={running || isScanning}>
          {isScanning ? <><span class="spinner" /> Scanning...</> : 'Start'}
        </button>
        <button class="btn btn-red" onClick={stop} disabled={!running && !isScanning}>
          Stop
        </button>
      </div>

      <div class="observer-hint">
        Start runs one scan, then launches the observer and refreshes client data every 20 seconds.
      </div>

      {(scanNetworks.length > 0 || isScanning || scanComplete) && (
        <div class="panel">
          <div class="panel-header">
            <span>Scan Results ({scanNetworks.length})</span>
            {scanComplete && <span class="badge badge-cyan">ready</span>}
          </div>
          <div class="panel-body" style="max-height:40vh;overflow-y:auto;padding:0">
            <ScanResultsPreview networks={scanNetworks} />
          </div>
        </div>
      )}

      <div class="panel">
        <div class="panel-header">
          <span>Observed Clients</span>
          {running && isRefreshing && <span class="badge badge-cyan">refreshing</span>}
        </div>
        <div class="panel-body">
          {hasSnapshot ? <SnifferResultsTable aps={aps} /> : (
            <div class="empty-msg">
              {running ? 'Waiting for first observer snapshot...' : 'Press Start to begin observing.'}
            </div>
          )}
        </div>
      </div>

      <AttackMonitor title="Network Observer Monitor" attackType="sniffer" />
    </Layout>
  );
}
