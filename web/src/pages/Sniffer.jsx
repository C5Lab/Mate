import { useEffect, useRef, useState } from 'preact/hooks';
import { route } from 'preact-router';
import { Layout } from '../components/Layout';
import { api } from '../api';
import { setState } from '../store';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';

const REFRESH_INTERVAL_MS = 4000;
const RESULTS_POLL_MS = 2000;
const SCAN_POLL_MS = 2000;
const SCAN_TIMEOUT_MS = 60000;

/* Merge a fresh sniffer snapshot into the current list without ever dropping
 * an AP we already saw. Each refresh from JanOS may transiently report fewer
 * APs/clients (e.g. between captures), and we don't want the UI to blink. */
function mergeAps(prev, fresh) {
  const map = new Map();
  for (const a of prev) {
    map.set(`${a.ssid}__${a.channel}`, { ...a, clients: [...(a.clients || [])] });
  }
  for (const a of fresh) {
    const key = `${a.ssid}__${a.channel}`;
    const existing = map.get(key);
    if (existing) {
      const all = new Set([...(existing.clients || []), ...(a.clients || [])]);
      existing.clients = [...all];
      existing.clientCount = Math.max(existing.clientCount || 0, a.clientCount || all.size);
      existing.channel = a.channel || existing.channel;
    } else {
      map.set(key, { ...a, clients: [...(a.clients || [])] });
    }
  }
  return [...map.values()];
}

function mergeProbes(prev, fresh) {
  const map = new Map();
  for (const p of prev) map.set(p.ssid || `__idx${p.index}`, p);
  for (const p of fresh) map.set(p.ssid || `__idx${p.index}`, p);
  return [...map.values()].sort((a, b) => (a.index || 0) - (b.index || 0));
}

function NetworkRow({ ap, expanded, onToggle }) {
  const clientCount = ap.clientCount || 0;
  const clients = ap.clients || [];

  return (
    <li class={`observer-net ${expanded ? 'open' : ''}`}>
      <button class="observer-net-header" onClick={onToggle}>
        <span class={`observer-chevron ${expanded ? 'open' : ''}`}>▸</span>
        <span class="observer-ssid">{ap.ssid || 'Unknown'}</span>
        <span class="observer-net-meta">CH{ap.channel}</span>
        <span class={`badge ${clientCount > 0 ? 'ok' : ''}`}>{clientCount} clients</span>
      </button>
      {expanded ? (
        <ul class="observer-clients">
          {clients.length > 0 ? clients.map((mac) => (
            <li class="observer-client" key={`${ap.ssid}-${mac}`}>{mac}</li>
          )) : (
            <li class="observer-client empty">Waiting for client list...</li>
          )}
        </ul>
      ) : null}
    </li>
  );
}

function NetworksPanel({ aps }) {
  const [expandedKey, setExpandedKey] = useState(null);

  if (!aps.length) {
    return <div class="empty-state">No APs with clients yet. Keep observer running.</div>;
  }

  const sorted = [...aps].sort((a, b) => (b.clientCount || 0) - (a.clientCount || 0));

  return (
    <ul class="observer-net-list">
      {sorted.map((ap) => {
        const key = `${ap.ssid}-${ap.channel}`;
        const expanded = expandedKey === key;
        return (
          <NetworkRow
            ap={ap}
            expanded={expanded}
            onToggle={() => setExpandedKey(expanded ? null : key)}
            key={key}
          />
        );
      })}
    </ul>
  );
}

function ProbesPanel({ probes, onPick }) {
  if (!probes.length) {
    return <div class="empty-state">No probes captured yet.</div>;
  }

  return (
    <ul class="probe-list">
      {probes.map((p) => (
        <li key={`${p.index}-${p.ssid}`}>
          <button class="probe-item" onClick={() => onPick(p)}>
            <span class="probe-idx">{p.index}</span>
            <span class="probe-ssid">{p.ssid || '[hidden]'}</span>
            <span class="probe-cta">Karma →</span>
          </button>
        </li>
      ))}
    </ul>
  );
}

export function Sniffer() {
  const [running, setRunning] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [packetCount, setPacketCount] = useState(0);
  const [aps, setAps] = useState([]);
  const [probes, setProbes] = useState([]);
  const refreshTimerRef = useRef(null);
  const resultsPollRef = useRef(null);
  const scanPollRef = useRef(null);
  const scanTimeoutRef = useRef(null);
  const refreshTickRef = useRef(0);

  const apCount = aps.length;
  const clientTotal = aps.reduce((sum, ap) => sum + (ap.clientCount || 0), 0);

  useEffect(() => {
    (async () => {
      try {
        const status = await api.status();
        if (status?.ok && status.state === 'sniffer') {
          setRunning(true);
          await loadSnifferResults();
          await loadProbes();
          startRefreshLoop();
          startResultsPoll();
        } else {
          await loadSnifferResults();
          await loadProbes();
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

      if (msg.type === 'probes_updated') {
        loadProbes();
      }

      if (msg.type === 'attack_started' && msg.attack === 'sniffer') {
        setRunning(true);
      }

      if (msg.type === 'attack_stopped') {
        stopAllTimers();
        setRunning(false);
        setIsScanning(false);
      }
    });

    return () => {
      stopAllTimers();
      removeWs();
    };
  }, []);

  function stopAllTimers() {
    if (refreshTimerRef.current) {
      clearInterval(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }
    if (resultsPollRef.current) {
      clearInterval(resultsPollRef.current);
      resultsPollRef.current = null;
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
      setState({ packetCount: data.packetCount || 0 });
      const fresh = Array.isArray(data.aps) ? data.aps : [];
      /* Only merge into the visible list when we got something. Empty refreshes
       * are common (firmware between snapshots) and would otherwise blank the
       * panel for the user. */
      if (fresh.length > 0) {
        setAps((prev) => mergeAps(prev, fresh));
      }
    } catch (e) {
      /* ignore */
    }
  }

  async function loadProbes() {
    try {
      const data = await api.probes();
      if (!data.ok || !Array.isArray(data.probes)) return;
      if (data.probes.length > 0) {
        setProbes((prev) => mergeProbes(prev, data.probes));
      }
    } catch (e) {
      /* ignore */
    }
  }

  async function tickRefresh() {
    /* Alternate between the two listing commands so JanOS never sees them
       overlap (each listing locks state until its prompt completes). */
    const tick = refreshTickRef.current++;
    try {
      if (tick % 2 === 0) {
        await api.refreshSniffer();
      } else {
        await api.refreshProbes();
      }
    } catch (e) { /* ignore */ }
  }

  async function refreshAll() {
    try { await api.refreshSniffer(); } catch (e) { /* ignore */ }
    setTimeout(async () => {
      try { await api.refreshProbes(); } catch (e) { /* ignore */ }
      /* Pull the freshly-collected snapshot over GET so the button works even
         when the WS push is lost under the packet-count flood. */
      setTimeout(() => {
        loadSnifferResults();
        loadProbes();
      }, 1200);
    }, 1000);
  }

  function startRefreshLoop() {
    if (refreshTimerRef.current) return;
    refreshTickRef.current = 0;
    refreshTimerRef.current = setInterval(tickRefresh, REFRESH_INTERVAL_MS);
  }

  /* Pull results over plain GET, independent of the WS push. The observer's
     structured events (sniffer_results_updated / probes_updated) can be dropped
     when the WS queue saturates under the sniffer packet-count flood, so we poll
     the cached snapshot directly to keep the UI live without a full reload. */
  function startResultsPoll() {
    if (resultsPollRef.current) return;
    resultsPollRef.current = setInterval(() => {
      loadSnifferResults();
      loadProbes();
    }, RESULTS_POLL_MS);
  }

  async function startSnifferAfterScan() {
    const res = await api.snifferNoscan();
    if (!res.ok) {
      showToast(res.error || 'Failed to start observer', 'error');
      setIsScanning(false);
      return;
    }

    setRunning(true);
    setIsScanning(false);
    setPacketCount(0);
    setAps([]);
    setProbes([]);
    await loadSnifferResults();
    await loadProbes();
    startRefreshLoop();
    startResultsPoll();
    showToast('Network Observer started', 'success');
  }

  async function start() {
    stopAllTimers();
    setIsScanning(true);
    setRunning(false);
    setPacketCount(0);
    setAps([]);
    setProbes([]);
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

        setState({ networks: data.networks || [], selected: new Set() });

        if (data.complete) {
          if (scanPollRef.current) {
            clearInterval(scanPollRef.current);
            scanPollRef.current = null;
          }
          if (scanTimeoutRef.current) {
            clearTimeout(scanTimeoutRef.current);
            scanTimeoutRef.current = null;
          }
          showToast(`Scan complete: ${data.count} networks`, 'success');
          await startSnifferAfterScan();
        }
      } catch (e) {
        /* ignore poll error */
      }
    }, SCAN_POLL_MS);

    scanTimeoutRef.current = setTimeout(() => {
      stopAllTimers();
      setIsScanning(false);
      showToast('Scan timed out', 'warning');
    }, SCAN_TIMEOUT_MS);
  }

  async function stop() {
    stopAllTimers();
    await api.stop();
    setRunning(false);
    setIsScanning(false);
    showToast('Observer stopped', 'warning');
  }

  function pickProbe(probe) {
    route(`/karma?probe=${probe.index}&ssid=${encodeURIComponent(probe.ssid || '')}`);
  }

  return (
    <Layout
      title="Network Observer"
      back="/"
    >
      <section class="glass-card card-body reveal">
        <div class="stats-grid" style="grid-template-columns: repeat(4, minmax(0, 1fr));">
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
          <article class="stat-card">
            <div class="stat-label">Probes</div>
            <div class="stat-value">{probes.length}</div>
          </article>
        </div>

        <div class="btn-row">
          <button class="btn btn-success" onClick={start} disabled={running || isScanning}>
            {isScanning ? <><span class="spinner" /> Scanning...</> : 'Start Observer'}
          </button>
          <button class="btn btn-secondary" onClick={refreshAll} disabled={!running}>
            Refresh
          </button>
          <button class="btn btn-danger" onClick={stop} disabled={!running && !isScanning}>
            Stop
          </button>
        </div>

        <div class="section-note">
          Start runs one scan, then launches sniffer (noscan) and refreshes clients + probes every 4s.
        </div>
      </section>

      <div class="observer-grid">
        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">Observed Networks</h3>
            <span class={`badge ${running ? 'ok' : ''}`}>{running ? 'Live' : 'Idle'}</span>
          </div>
          <NetworksPanel aps={aps} />
        </section>

        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">Probe Requests</h3>
            <span class="badge">{probes.length}</span>
          </div>
          <div class="section-note" style="margin-top:0;margin-bottom:8px">
            Click a probe to launch Karma against it.
          </div>
          <ProbesPanel probes={probes} onPick={pickProbe} />
        </section>
      </div>
    </Layout>
  );
}
