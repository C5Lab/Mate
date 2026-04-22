import { route } from 'preact-router';
import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { NetworkList } from '../components/NetworkList';
import { api } from '../api';
import { getState, setAllNetworks, setState, toggleNetwork } from '../store';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';

let pollTimer = null;
let pollTimeout = null;

const ATTACK_OPTIONS = [
  { id: 'deauth', label: 'Deauth', available: true },
  { id: 'eviltwin', label: 'Evil Twin', available: true },
  { id: 'rogueap', label: 'Rogue AP', available: true },
  { id: 'handshake', label: 'Handshaker', available: true },
  { id: 'sae', label: 'SAE Overflow', available: true },
  { id: 'sniffer', label: 'Observer', available: true },
  { id: 'mitm', label: 'MITM', available: true },
  { id: 'nmap', label: 'Nmap', available: true },
  { id: 'arp', label: 'ARP', available: true },
];

const STA_REQUIRED_ATTACKS = new Set(['mitm', 'nmap', 'arp']);

function isOpenSecurity(security) {
  return !security || /open/i.test(security);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  if (pollTimeout) {
    clearTimeout(pollTimeout);
    pollTimeout = null;
  }
}

export function Scan() {
  const [attack, setAttack] = useState('deauth');
  const [serialLines, setSerialLines] = useState([]);
  const [attackLive, setAttackLive] = useState(false);

  const [connectOpen, setConnectOpen] = useState(false);
  const [connectSsid, setConnectSsid] = useState('');
  const [connectSecurity, setConnectSecurity] = useState('');
  const [connectPassword, setConnectPassword] = useState('');
  const [connectBusy, setConnectBusy] = useState(false);
  const [connectError, setConnectError] = useState('');

  const [monitorOpen, setMonitorOpen] = useState(false);
  const [monitorTitle, setMonitorTitle] = useState('');
  const [monitorAttack, setMonitorAttack] = useState('');
  const [monitorLines, setMonitorLines] = useState([]);
  const [arpRows, setArpRows] = useState([]);
  const [nmapRows, setNmapRows] = useState([]);

  const pendingRef = useRef(null);
  const connectOutcomeRef = useRef(null);
  const monitorAttackRef = useRef('');
  const monitorOpenRef = useRef(false);
  const currentNmapHostRef = useRef('');

  const st = getState();
  const scanning = st.status === 'scanning' || st.status === 'scan';
  const selectedAttack = ATTACK_OPTIONS.find((opt) => opt.id === attack);

  useEffect(() => {
    const removeWs = wsAddListener((msg) => {
      if (msg.type === 'attack_started') {
        setAttackLive(true);
        pushLine(`${msg.attack || 'operation'} started`);
      }

      if (msg.type === 'attack_stopped') {
        setAttackLive(false);
        pushLine('operation stopped');
      }

      if (msg.type === 'wifi_connecting') {
        pushLine('wifi_connect started');
      }

      if (msg.type === 'wifi_connected') {
        connectOutcomeRef.current = { ok: true };
        pushLine('wifi connected');
      }

      if (msg.type === 'wifi_connect_failed') {
        connectOutcomeRef.current = { ok: false, error: 'FAILED/TIMEOUT' };
        pushLine('wifi connect failed');
      }

      if (msg.type === 'wifi_disconnected') {
        pushLine('wifi disconnected');
      }

      if (msg.type === 'uart_line' && msg.data) {
        pushLine(msg.data);
        pushMonitorLine(msg.data);
      }
    });

    return () => {
      stopPolling();
      removeWs();
    };
  }, []);

  function pushLine(text) {
    const trimmed = String(text || '').trim();
    if (!trimmed) return;
    setSerialLines((prev) => [...prev, trimmed].slice(-3));
  }

  function openMonitor(nextAttack, title) {
    monitorOpenRef.current = true;
    monitorAttackRef.current = nextAttack;
    currentNmapHostRef.current = '';
    setMonitorOpen(true);
    setMonitorAttack(nextAttack);
    setMonitorTitle(title || 'Attack Monitor');
    setMonitorLines([]);
    setArpRows([]);
    setNmapRows([]);
  }

  function closeMonitor() {
    monitorOpenRef.current = false;
    monitorAttackRef.current = '';
    currentNmapHostRef.current = '';
    setMonitorOpen(false);
  }

  function parseArpLine(line) {
    const m = line.match(/^\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*->\s*([0-9A-Fa-f:]{17})\s*$/);
    if (!m) return;
    const ip = m[1];
    const mac = m[2].toUpperCase();
    setArpRows((prev) => {
      if (prev.some((row) => row.ip === ip && row.mac === mac)) return prev;
      return [...prev, { ip, mac }];
    });
  }

  function upsertNmapHost(ip, mac) {
    setNmapRows((prev) => {
      const idx = prev.findIndex((row) => row.ip === ip);
      if (idx >= 0) {
        const next = [...prev];
        next[idx] = { ...next[idx], mac: mac || next[idx].mac };
        return next;
      }
      return [...prev, { ip, mac: mac || 'MAC unknown', ports: [] }];
    });
  }

  function addNmapPort(ip, port, service) {
    setNmapRows((prev) => {
      const idx = prev.findIndex((row) => row.ip === ip);
      if (idx < 0) return prev;
      const exists = prev[idx].ports.some((p) => p.port === port);
      if (exists) return prev;
      const next = [...prev];
      next[idx] = {
        ...next[idx],
        ports: [...next[idx].ports, { port, service }],
      };
      return next;
    });
  }

  function parseNmapLine(line) {
    const host = line.match(/^Host:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+\(([^)]+)\)\s*$/i);
    if (host) {
      const ip = host[1];
      const mac = host[2];
      currentNmapHostRef.current = ip;
      upsertNmapHost(ip, mac);
      return;
    }

    const port = line.match(/^\s*(\d+)\/tcp\s+open\s+([A-Za-z0-9_.-]+)\s*$/i);
    if (port && currentNmapHostRef.current) {
      addNmapPort(currentNmapHostRef.current, Number(port[1]), port[2]);
    }
  }

  function pushMonitorLine(text) {
    if (!monitorOpenRef.current) return;
    const trimmed = String(text || '').trim();
    if (!trimmed) return;

    setMonitorLines((prev) => [...prev, trimmed].slice(-240));

    if (monitorAttackRef.current === 'arp') {
      parseArpLine(trimmed);
    } else if (monitorAttackRef.current === 'nmap') {
      parseNmapLine(trimmed);
    }
  }

  function pickStrongestSelectedNetwork(selectedIndices) {
    const selected = st.networks.filter((n) => selectedIndices.includes(n.index));
    if (!selected.length) return null;
    return selected.reduce((best, n) => (n.rssi > best.rssi ? n : best), selected[0]);
  }

  async function doScan() {
    stopPolling();
    setState({ networks: [], selected: new Set(), status: 'scanning' });

    try {
      const res = await api.scan();
      if (!res.ok) {
        showToast(res.error || 'Scan unavailable', 'error');
        setState({ status: 'idle' });
        return;
      }
    } catch (e) {
      showToast('Scan failed', 'error');
      setState({ status: 'idle' });
      return;
    }

    pollTimer = setInterval(async () => {
      try {
        const data = await api.scanResults();
        if (!data.ok) return;

        setState({ networks: data.networks || [], scanCount: data.count || 0 });

        if (data.complete) {
          stopPolling();
          setState({ status: 'idle', lastScanAt: Date.now() });
          showToast(`Scan complete: ${data.networks.length} APs`, 'success');
        }
      } catch (e) {
        /* keep polling */
      }
    }, 1800);

    pollTimeout = setTimeout(() => {
      stopPolling();
      if (getState().status === 'scanning' || getState().status === 'scan') {
        setState({ status: 'idle' });
        showToast('Scan timed out', 'warning');
      }
    }, 70000);
  }

  async function runAttackWithMonitor(attackId, label, runner) {
    openMonitor(attackId, `${label} Serial`);
    const res = await runner();
    if (res.ok) {
      showToast(`${attackId} started`, 'success');
      setAttackLive(true);
      pushLine(`${attackId} started`);
      if (attackId === 'sniffer') route('/sniffer');
    } else {
      pushMonitorLine(`Error: ${res.error || 'failed to start attack'}`);
      showToast(res.error || 'Failed to start attack', 'error');
    }
  }

  async function waitForWifiConnection(targetSsid, timeoutMs = 30000) {
    const started = Date.now();
    while (Date.now() - started < timeoutMs) {
      if (connectOutcomeRef.current?.ok === true) {
        return { ok: true };
      }
      if (connectOutcomeRef.current?.ok === false) {
        return { ok: false, error: connectOutcomeRef.current.error || 'connection failed' };
      }

      try {
        const status = await api.status();
        if (
          status?.ok &&
          status.sta_connected &&
          (!status.sta_ssid || status.sta_ssid === targetSsid)
        ) {
          return { ok: true };
        }
      } catch (e) {
        /* poll continues */
      }
      await sleep(1000);
    }
    return { ok: false, error: 'timeout' };
  }

  async function connectAndLaunchPending() {
    const pending = pendingRef.current;
    if (!pending) return;

    setConnectBusy(true);
    setConnectError('');
    connectOutcomeRef.current = null;
    setConnectOpen(false);

    openMonitor(pending.id, `${pending.label} Serial`);
    pushMonitorLine(`Connecting to ${pending.target.ssid}...`);

    const connectRes = await api.wifiConnect(pending.target.ssid, connectPassword.trim());
    if (!connectRes.ok) {
      setConnectBusy(false);
      setConnectError(connectRes.error || 'wifi_connect rejected');
      setConnectOpen(true);
      pushMonitorLine(`wifi_connect error: ${connectRes.error || 'rejected'}`);
      return;
    }

    const waitRes = await waitForWifiConnection(pending.target.ssid, 35000);
    if (!waitRes.ok) {
      setConnectBusy(false);
      setConnectError(waitRes.error || 'Connection failed');
      setConnectOpen(true);
      pushMonitorLine(`Connection failed: ${waitRes.error || 'unknown'}`);
      showToast('WiFi connect failed', 'error');
      return;
    }

    pushMonitorLine('Connected. Starting attack...');
    const runRes = await pending.runner();
    setConnectBusy(false);
    pendingRef.current = null;

    if (runRes.ok) {
      setAttackLive(true);
      showToast(`${pending.id} started`, 'success');
    } else {
      pushMonitorLine(`Attack start failed: ${runRes.error || 'unknown error'}`);
      showToast(runRes.error || 'Failed to start attack', 'error');
    }
  }

  async function launchAttack() {
    const state = getState();
    const targets = Array.from(state.selected);

    if (!targets.length) {
      showToast('Select a target network first', 'warning');
      return;
    }

    if (!selectedAttack?.available) {
      showToast(`${selectedAttack.label} is not available`, 'warning');
      return;
    }

    if (attack === 'sae' && targets.length !== 1) {
      showToast('SAE Overflow requires exactly 1 target', 'warning');
      return;
    }

    await api.select(targets);

    if (attack === 'eviltwin') {
      route('/eviltwin');
      return;
    }

    if (attack === 'rogueap') {
      route('/rogueap');
      return;
    }

    const runner = {
      deauth: api.deauth,
      handshake: api.handshake,
      sae: api.sae,
      sniffer: api.sniffer,
      mitm: api.mitm,
      nmap: api.nmap,
      arp: api.arp,
    }[attack];

    if (!runner) {
      showToast('Attack endpoint is not available yet', 'warning');
      return;
    }

    if (STA_REQUIRED_ATTACKS.has(attack)) {
      const target = pickStrongestSelectedNetwork(targets);
      if (!target || !target.ssid) {
        showToast('Select a network with visible SSID for this attack', 'warning');
        return;
      }

      const status = await api.status().catch(() => null);
      const alreadyConnected = !!(
        status?.ok &&
        status.sta_connected &&
        status.sta_ssid &&
        status.sta_ssid === target.ssid
      );

      if (!alreadyConnected) {
        pendingRef.current = {
          id: attack,
          label: selectedAttack.label,
          runner,
          target,
        };
        setConnectSsid(target.ssid);
        setConnectSecurity(target.security || '');
        setConnectPassword('');
        setConnectError('');
        setConnectOpen(true);
        return;
      }

      await runAttackWithMonitor(attack, selectedAttack.label, runner);
      return;
    }

    const res = await runner();
    if (res.ok) {
      showToast(`${attack} started`, 'success');
      setAttackLive(true);
      pushLine(`${attack} started`);
      if (attack === 'sniffer') route('/sniffer');
    } else {
      showToast(res.error || 'Failed to start attack', 'error');
    }
  }

  async function stopAndClosePopup() {
    await api.stop();
    setAttackLive(false);
    setConnectOpen(false);
    closeMonitor();
    pendingRef.current = null;
    setConnectBusy(false);
    connectOutcomeRef.current = { ok: false, error: 'stopped' };
    showToast('Stop sent', 'warning');
  }

  async function stopAll() {
    await api.stop();
    setState({ status: 'idle' });
    showToast('Stop sent', 'warning');
  }

  return (
    <Layout
      title="Scan"
      back="/"
    >
      <section class="glass-card card-body reveal">
        <div class="btn-row">
          <button class="btn btn-info" onClick={doScan} disabled={scanning}>
            {scanning ? <span class="spinner" /> : null}
            {scanning ? 'Scanning...' : 'Start Scan'}
          </button>
          <button class="btn btn-danger" onClick={stopAll}>
            Stop
          </button>
        </div>
      </section>

      <NetworkList
        networks={st.networks}
        selected={st.selected}
        onToggle={toggleNetwork}
        onToggleAll={setAllNetworks}
      />

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Attack Selection</h3>
        </div>
        <div class="attack-picker">
          {ATTACK_OPTIONS.map((opt) => (
            <button
              key={opt.id}
              class={`attack-chip ${attack === opt.id ? 'active' : ''} ${opt.available ? '' : 'coming-soon'}`}
              onClick={() => setAttack(opt.id)}
            >
              {opt.label}
              {!opt.available ? <span class="chip-mini">Soon</span> : null}
            </button>
          ))}
        </div>
        <button class="btn btn-primary" onClick={launchAttack} disabled={!st.selected.size || scanning}>
          Launch {selectedAttack?.label}
        </button>
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Serial</h3>
          <span class={`badge ${attackLive ? 'ok' : ''}`}>{attackLive ? 'Live' : 'Idle'}</span>
        </div>
        <div class="mini-serial">
          {serialLines.length ? (
            serialLines.map((line, idx) => (
              <div class="mini-serial-line" key={`${idx}-${line}`}>
                {line}
              </div>
            ))
          ) : (
            <div class="mini-serial-line empty">No live output</div>
          )}
        </div>
      </section>

      {connectOpen ? (
        <div class="scan-modal-overlay">
          <section class="glass-card scan-modal scan-modal-compact">
            <div class="scan-modal-head">
              <h3 class="section-title">WiFi Connect Required</h3>
              <span class="badge info">{connectSsid}</span>
            </div>

            <div class="field">
              <label class="field-label">Password</label>
              <input
                class="input"
                type="password"
                value={connectPassword}
                onInput={(e) => setConnectPassword(e.target.value)}
                placeholder={isOpenSecurity(connectSecurity) ? 'Optional for open network' : 'Enter WiFi password'}
              />
            </div>

            {connectError ? <div class="alert warn">{connectError}</div> : null}

            <div class="btn-row">
              <button class="btn btn-info" disabled={connectBusy} onClick={connectAndLaunchPending}>
                {connectBusy ? <span class="spinner" /> : null}
                Connect & Run
              </button>
              <button class="btn btn-danger" onClick={stopAndClosePopup}>
                Stop
              </button>
            </div>
          </section>
        </div>
      ) : null}

      {monitorOpen ? (
        <div class="scan-modal-overlay">
          <section class="glass-card scan-modal">
            <div class="scan-modal-head">
              <h3 class="section-title">{monitorTitle}</h3>
              <span class={`badge ${attackLive ? 'ok' : ''}`}>{attackLive ? 'Live' : 'Idle'}</span>
            </div>

            <div class="scan-modal-serial">
              {monitorLines.length ? (
                monitorLines.map((line, idx) => (
                  <div class="scan-modal-line" key={`${idx}-${line}`}>
                    {line}
                  </div>
                ))
              ) : (
                <div class="scan-modal-line empty">Waiting for serial output...</div>
              )}
            </div>

            {monitorAttack === 'arp' ? (
              <div class="table-wrap">
                <table class="table">
                  <thead>
                    <tr>
                      <th>IP</th>
                      <th>MAC</th>
                    </tr>
                  </thead>
                  <tbody>
                    {!arpRows.length ? (
                      <tr>
                        <td colSpan={2}>No hosts discovered yet</td>
                      </tr>
                    ) : (
                      arpRows.map((row) => (
                        <tr key={`${row.ip}-${row.mac}`}>
                          <td>{row.ip}</td>
                          <td>{row.mac}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            ) : null}

            {monitorAttack === 'nmap' ? (
              <div class="table-wrap">
                <table class="table">
                  <thead>
                    <tr>
                      <th>Host</th>
                      <th>MAC</th>
                      <th>Open Ports</th>
                    </tr>
                  </thead>
                  <tbody>
                    {!nmapRows.length ? (
                      <tr>
                        <td colSpan={3}>No hosts detected yet</td>
                      </tr>
                    ) : (
                      nmapRows.map((row) => (
                        <tr key={row.ip}>
                          <td>{row.ip}</td>
                          <td>{row.mac}</td>
                          <td>
                            {row.ports.length
                              ? row.ports.map((p) => `${p.port}/${p.service}`).join(', ')
                              : '-'}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            ) : null}

            <div class="btn-row">
              <button class="btn btn-danger" onClick={stopAndClosePopup}>
                Stop
              </button>
              <button class="btn btn-secondary" onClick={closeMonitor}>
                Close
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </Layout>
  );
}
