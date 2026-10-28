import { route } from 'preact-router';
import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { NetworkList } from '../components/NetworkList';
import { api } from '../api';
import { clearArpHosts, getState, setAllNetworks, setArpHosts, setAttackRunning, setState, subscribe, toggleNetwork } from '../store';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';

let pollTimer = null;
let pollTimeout = null;
let arpPollTimer = null;
let arpPollInFlight = false;
let nmapPollTimer = null;
let nmapPollInFlight = false;

function stopArpPolling() {
  if (arpPollTimer) {
    clearInterval(arpPollTimer);
    arpPollTimer = null;
  }
  arpPollInFlight = false;
}

async function fetchArpHosts() {
  if (arpPollInFlight) return;
  arpPollInFlight = true;
  try {
    const res = await api.arpHosts();
    if (res?.ok && Array.isArray(res.hosts)) {
      setArpHosts(res.hosts, res.at || Date.now());
    }
  } catch (e) {
    /* transient network failure -- next tick will retry */
  } finally {
    arpPollInFlight = false;
  }
}

function startArpPolling() {
  if (arpPollTimer) return;
  /* Kick once immediately so the UI doesn't wait the first 1.5 s before
   * showing what's already cached on the device (e.g. when navigating
   * back into the monitor after a reload). */
  fetchArpHosts();
  arpPollTimer = setInterval(fetchArpHosts, 1500);
}

/* Nmap polling. The on-device cache (`/api/nmap/results`) is the source of
 * truth: heavy scans take minutes during which the softAP channel hops to
 * track the STA, and the WS to the phone routinely drops mid-scan. With
 * polling the UI reconverges as soon as the WS comes back and never
 * silently misses a discovery. The component installs/uninstalls the
 * polling fetch via the helpers below; the timer is module-scoped so the
 * teardown hook can stop it even if the component unmounts mid-tick. */
function stopNmapPolling() {
  if (nmapPollTimer) {
    clearInterval(nmapPollTimer);
    nmapPollTimer = null;
  }
  nmapPollInFlight = false;
}

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
  { id: 'gitm', label: 'GITM', available: true },
  { id: 'rogue_gitm', label: 'Rogue GITM', available: true },
];

const STA_REQUIRED_ATTACKS = new Set(['mitm', 'nmap', 'arp']);
const NMAP_LEVELS = ['quick', 'medium', 'heavy'];

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

  const [connectOpen, setConnectOpen] = useState(false);
  const [connectSsid, setConnectSsid] = useState('');
  const [connectVendor, setConnectVendor] = useState('');
  const [connectSecurity, setConnectSecurity] = useState('');
  const [connectPassword, setConnectPassword] = useState('');
  const [connectBusy, setConnectBusy] = useState(false);
  const [connectError, setConnectError] = useState('');

  const [monitorOpen, setMonitorOpen] = useState(false);
  const [monitorTitle, setMonitorTitle] = useState('');
  const [monitorAttack, setMonitorAttack] = useState('');
  const [monitorLines, setMonitorLines] = useState([]);
  const [, forceArpRender] = useState(0);
  const [arpBanTarget, setArpBanTarget] = useState(null); // { ip, mac } currently being banned
  const [arpBanBusy, setArpBanBusy] = useState(false);
  const [nmapRows, setNmapRows] = useState([]);
  const [nmapLevel, setNmapLevel] = useState('quick');
  const [nmapStats, setNmapStats] = useState({
    level: '',
    totalHosts: 0,
    scanningHost: '',
    portTotal: 0,
    portCurrent: 0,
    summary: '',
    done: false,
  });
  const [nmapSetupOpen, setNmapSetupOpen] = useState(false);
  const [nmapSetupBusy, setNmapSetupBusy] = useState(false);
  const [nmapSetupError, setNmapSetupError] = useState('');

  const pendingRef = useRef(null);
  const connectOutcomeRef = useRef(null);
  const monitorAttackRef = useRef('');
  const monitorOpenRef = useRef(false);
  const nmapDiscoveryActiveRef = useRef(false);

  const st = getState();
  /* Attack lock now lives in the global store (reconciled from /api/status in
   * app.jsx) so it survives navigation, WS reconnects and disconnect→return. */
  const attackLive = st.attackRunning;
  const scanning = st.status === 'scanning' || st.status === 'scan';
  const selectedAttack = ATTACK_OPTIONS.find((opt) => opt.id === attack);
  const arpRows = st.arpHosts || [];

  /* Re-render whenever the global store updates so newly-discovered ARP
   * hosts appear in the panel even if they arrived while the monitor was
   * still being opened (or before this page was mounted). */
  useEffect(() => subscribe(() => forceArpRender((n) => n + 1)), []);

  useEffect(() => {
    const removeWs = wsAddListener((msg) => {
      if (msg.type === 'attack_started') {
        /* The attack lock itself is global now (st.attackRunning): armed
         * optimistically on Launch + on the WS attack_started fast-path in
         * app.jsx, and reconciled/cleared by the /api/status poll. This local
         * handler only maintains the serial breadcrumb + ARP polling. */
        pushLine(`${msg.attack || 'operation'} started`);
        if (msg.attack === 'arp') {
          /* Make sure we're polling -- covers the case where the monitor
           * was opened before this listener was wired up and also gives
           * us a head-start for fetching the cache. */
          startArpPolling();
          fetchArpHosts();
        }
      }

      if (msg.type === 'attack_stopped') {
        pushLine('operation stopped');
        if (monitorAttackRef.current === 'arp') {
          /* One last fetch so we don't miss hosts that landed between the
           * previous tick and the stop event, then keep polling for as
           * long as the monitor is still open in case the user re-runs. */
          fetchArpHosts();
        }
        if (nmapDiscoveryActiveRef.current) {
          /* list_hosts finished while the nmap setup popup is open. Flip
           * out of busy so the user can pick a target (or ALL). */
          fetchArpHosts();
          setNmapSetupBusy(false);
        }
      }

      if (msg.type === 'wifi_connecting') {
        pushLine('wifi_connect started');
      }

      if (msg.type === 'wifi_connected') {
        connectOutcomeRef.current = { ok: true };
        pushLine('wifi connected');
      }

      if (msg.type === 'wifi_connect_failed') {
        connectOutcomeRef.current = { ok: false, error: 'FAILED/TIMEOUT', at: Date.now() };
        pushLine('wifi connect failed');
      }

      if (msg.type === 'wifi_disconnected') {
        pushLine('wifi disconnected');
      }

      /* Raw serial no longer comes from the WS (it drops frames here) — the
       * serial poll below feeds pushLine/pushMonitorLine reliably. */

      if (msg.type === 'nmap_results') {
        /* Instant update from the device-side incremental broadcast. The
         * polling fetch is the safety net for when this event is dropped
         * (which routinely happens during heavy scans because the softAP
         * channel hops to track the STA). */
        applyNmapResults(msg);
      }

      if (msg.type === 'scan_complete') {
        // Bug 1: don't wait another poll tick -- pull final results
        // immediately and stop the local poller so the UI flips out of
        // "Scanning..." the moment Mate confirms completion.
        stopPolling();
        api.scanResults().then((data) => {
          if (data?.ok) {
            setState({
              networks: data.networks || [],
              scanCount: data.count || 0,
              status: 'idle',
              lastScanAt: Date.now(),
            });
            showToast(`Scan complete: ${(data.networks || []).length} APs`, 'success');
          } else {
            setState({ status: 'idle' });
          }
        }).catch(() => setState({ status: 'idle' }));
      }
    });

    /* Reliable serial + attack-lock via HTTP polling (the WS drops frames in
     * some environments, which left the Serial panel blank and the attack
     * lock flapping). */
    let serialSeq = 0;
    const serialTimer = setInterval(async () => {
      try {
        const res = await api.serialTail(serialSeq);
        if (!res?.ok) return;
        serialSeq = res.seq || 0;
        if (Array.isArray(res.lines)) {
          for (const ln of res.lines) { pushLine(ln); pushMonitorLine(ln); }
        }
      } catch (e) { /* ignore */ }
    }, 1000);

    return () => {
      clearInterval(serialTimer);
      stopPolling();
      stopArpPolling();
      stopNmapPolling();
      removeWs();
    };
  }, []);

  function pushLine(text) {
    const trimmed = String(text || '').trim();
    if (!trimmed) return;
    setSerialLines((prev) => [...prev, trimmed].slice(-8));
  }

  function openMonitor(nextAttack, title) {
    monitorOpenRef.current = true;
    monitorAttackRef.current = nextAttack;
    setMonitorOpen(true);
    setMonitorAttack(nextAttack);
    setMonitorTitle(title || 'Attack Monitor');
    setMonitorLines([]);
    if (nextAttack === 'arp') {
      clearArpHosts();
      /* Start polling /api/arp/hosts so the table populates even if the
       * `arp_hosts` WS event was lost (softAP channel hop right after STA
       * joins the victim AP routinely drops the WS for a few seconds). */
      startArpPolling();
    } else {
      stopArpPolling();
    }
    setArpBanTarget(null);
    setArpBanBusy(false);
    setNmapRows([]);
    setNmapStats({
      level: '',
      totalHosts: 0,
      scanningHost: '',
      portTotal: 0,
      portCurrent: 0,
      summary: '',
      done: false,
    });
  }

  function closeMonitor() {
    monitorOpenRef.current = false;
    monitorAttackRef.current = '';
    setMonitorOpen(false);
    stopArpPolling();
    stopNmapPolling();
  }

  function openNmapSetup() {
    /* Discover hosts on the LAN before launching the scan: this mirrors the
     * ARP attack flow and lets the user pick a single target (or ALL = full
     * subnet). We rely on api.arp() to send `list_hosts`, which populates
     * `arpHosts` in the global store via the WS `arp_hosts` event (with a
     * polling fallback). */
    nmapDiscoveryActiveRef.current = true;
    clearArpHosts();
    setNmapSetupError('');
    setNmapSetupBusy(true);
    setNmapSetupOpen(true);
    startArpPolling();

    return api.arp().then((res) => {
      if (!res?.ok) {
        setNmapSetupBusy(false);
        setNmapSetupError(res?.error || 'list_hosts rejected');
      }
      return res;
    }).catch(() => {
      setNmapSetupBusy(false);
      setNmapSetupError('list_hosts request failed');
      return { ok: false };
    });
  }

  function closeNmapSetup() {
    nmapDiscoveryActiveRef.current = false;
    setNmapSetupOpen(false);
    setNmapSetupBusy(false);
    stopArpPolling();
  }

  async function pickNmapTarget(targetIp) {
    /* targetIp = '' → ALL (entire subnet). The C handler treats an empty
     * IP as "no host argument" → JanOS scans the whole subnet. */
    nmapDiscoveryActiveRef.current = false;
    setNmapSetupOpen(false);
    setNmapSetupBusy(false);
    stopArpPolling();

    openMonitor('nmap', `Nmap Serial`);
    setNmapStats((s) => ({ ...s, level: nmapLevel }));
    pushMonitorLine(
      `Starting start_nmap ${nmapLevel}${targetIp ? ` ${targetIp}` : ''} ` +
      `(${targetIp ? `single host ${targetIp}` : 'whole subnet'})...`
    );

    /* Start polling the device-side nmap cache (`/api/nmap/results`).
     * Heavy scans drop the WS for tens of seconds at a time, so we treat
     * the polled snapshot as the source of truth for the results table. */
    startNmapPolling();

    const res = await api.nmap(nmapLevel, targetIp);
    if (res?.ok) {
      setAttackRunning(true);
      showToast(`nmap ${nmapLevel} started`, 'success');
    } else {
      pushMonitorLine(`Error: ${res?.error || 'nmap rejected'}`);
      showToast(res?.error || 'nmap failed', 'error');
      stopNmapPolling();
    }
  }

  function applyNmapResults(payload) {
    if (!payload) return;
    /* `count === 0` happens when the device has just been booted (or right
     * after `cmd_do_nmap` reset the cache and before the first port-scan
     * line came back) -- we still need to push the scan-level state in
     * (level, total_hosts, scanning, port progress) so the badges update. */
    setNmapRows(
      Array.isArray(payload.hosts)
        ? payload.hosts.map((h) => ({
            ip: h.ip,
            mac: h.mac || '',
            done: !!h.done,
            scanning: !h.done && h.ip === payload.scanning,
            noOpenPorts: !!h.no_open_ports,
            ports: Array.isArray(h.ports)
              ? h.ports.map((p) => ({ port: p.port, service: p.service || '' }))
              : [],
          }))
        : []
    );
    setNmapStats((prev) => ({
      ...prev,
      level: payload.level || prev.level,
      totalHosts: payload.total_hosts || prev.totalHosts,
      scanningHost: payload.scanning || '',
      portCurrent: payload.port_current || 0,
      portTotal: payload.port_total || prev.portTotal,
      done: !!payload.done,
      summary: payload.done
        ? `Scanned ${payload.total_hosts || (payload.hosts || []).length} ` +
          `host${(payload.total_hosts || 0) === 1 ? '' : 's'}, ` +
          `${payload.open_ports || 0} open port` +
          `${(payload.open_ports || 0) === 1 ? '' : 's'}`
        : prev.summary,
    }));

    /* Once the device reports completion we can stop polling -- there
     * won't be any more updates for this scan. */
    if (payload.done) {
      stopNmapPolling();
    }
  }

  async function fetchNmapResults() {
    if (nmapPollInFlight) return;
    nmapPollInFlight = true;
    try {
      const res = await api.nmapResults();
      if (res?.ok) applyNmapResults(res);
    } catch (e) {
      /* transient WS/HTTP failure -- next tick will retry */
    } finally {
      nmapPollInFlight = false;
    }
  }

  function startNmapPolling() {
    if (nmapPollTimer) return;
    fetchNmapResults();
    nmapPollTimer = setInterval(fetchNmapResults, 1500);
  }

  async function banArpHost(host) {
    if (!host || !host.mac) return;
    setArpBanBusy(true);
    pushMonitorLine(`Banning host ${host.ip} (${host.mac})...`);
    const res = await api.arpBan(host.mac, host.ip);
    setArpBanBusy(false);
    if (res?.ok) {
      setArpBanTarget(host);
      setAttackRunning(true);
      showToast(`ARP poisoning ${host.ip}`, 'success');
      pushMonitorLine(`arp_ban started for ${host.mac}`);
    } else {
      showToast(res?.error || 'arp_ban rejected', 'error');
      pushMonitorLine(`arp_ban error: ${res?.error || 'rejected'}`);
    }
  }

  /* parseArpLine moved to a global WS handler in app.jsx so hosts are
   * captured even if the Scan monitor isn't open (or if the user is on
   * another page). The Scan ARP panel reads from `getState().arpHosts`. */

  function pushMonitorLine(text) {
    if (!monitorOpenRef.current) return;
    const trimmed = String(text || '').trim();
    if (!trimmed) return;

    setMonitorLines((prev) => [...prev, trimmed].slice(-240));

    /* Nmap results are populated by `applyNmapResults` from the
     * polled `/api/nmap/results` snapshot (and the structured
     * `nmap_results` WS event when the WS is up); we don't parse the raw
     * UART lines here because the device-side cache already does that
     * and survives the WS dropping mid-scan. ARP host parsing is global
     * (see app.jsx wsAddListener) so it works whether or not the monitor
     * is open. */
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
    /* Nmap opens its own setup popup (host picker + mode picker) before the
     * real scan starts, so we deliberately don't open the standard monitor
     * here -- it would stack on top of the setup overlay. */
    if (attackId !== 'nmap') {
      openMonitor(attackId, `${label} Serial`);
    }
    const res = await runner();
    if (res.ok) {
      if (attackId !== 'nmap') {
        showToast(`${attackId} started`, 'success');
        setAttackRunning(true);
        pushLine(`${attackId} started`);
      }
      if (attackId === 'sniffer') route('/sniffer');
    } else {
      pushMonitorLine(`Error: ${res.error || 'failed to start attack'}`);
      showToast(res.error || 'Failed to start attack', 'error');
    }
  }

  async function waitForWifiConnection(targetSsid, timeoutMs = 30000) {
    const started = Date.now();
    let softFailure = null;

    while (Date.now() - started < timeoutMs) {
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

      if (connectOutcomeRef.current?.ok === true) {
        return { ok: true };
      }

      if (connectOutcomeRef.current?.ok === false) {
        if (!softFailure) {
          softFailure = {
            at: connectOutcomeRef.current.at || Date.now(),
            error: connectOutcomeRef.current.error || 'connection failed',
          };
        }
        if (Date.now() - softFailure.at > 2500) {
          return { ok: false, error: softFailure.error };
        }
      }

      await sleep(900);
    }

    return { ok: false, error: softFailure?.error || 'timeout' };
  }

  async function connectAndLaunchPending(passwordOverride) {
    const pending = pendingRef.current;
    if (!pending) return;

    // Bug 3: support auto-connect with a known password (from show_pass evil
    // cache) without going through the popup -- if passwordOverride is
    // provided we use it directly, otherwise fall back to whatever is in
    // the popup input.
    const password = (passwordOverride !== undefined ? passwordOverride : connectPassword).trim();

    setConnectBusy(true);
    setConnectError('');
    connectOutcomeRef.current = null;
    setConnectOpen(false);

    /* Don't clobber an already-open monitor (e.g. one we opened earlier
     * during the show_pass evil lookup) -- otherwise the breadcrumb log
     * the user is watching disappears the moment we connect.
     * Nmap is special: it opens a setup popup (not the streaming monitor)
     * after WiFi connects, so we don't open the monitor here for it. */
    if (pending.id !== 'nmap' &&
        (!monitorOpenRef.current || monitorAttackRef.current !== pending.id)) {
      openMonitor(pending.id, `${pending.label} Serial`);
    }
    pushMonitorLine(`Connecting to ${pending.target.ssid}...`);
    if (passwordOverride !== undefined) {
      pushMonitorLine('Using cached password from show_pass evil');
    }

    const connectRes = await api.wifiConnect(pending.target.ssid, password);
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
      /* Nmap reports "started" later (in pickNmapTarget) once the user has
       * picked a host and the actual `start_nmap` command has fired. Don't
       * mislead them by claiming nmap is live just because list_hosts ran. */
      if (pending.id !== 'nmap') {
        setAttackRunning(true);
        showToast(`${pending.id} started`, 'success');
      }
    } else {
      pushMonitorLine(`Attack start failed: ${runRes.error || 'unknown error'}`);
      showToast(runRes.error || 'Failed to start attack', 'error');
    }
  }

  // Bug 3: look up cached evil-twin password for the given SSID via
  // /api/passwords (which transparently triggers `show_pass evil` on the
  // C5 if the cache is empty). Polls a few times because the first call
  // may return `status: loading`.
  async function lookupCachedPassword(ssid) {
    if (!ssid) return null;
    for (let attempt = 0; attempt < 4; attempt++) {
      try {
        const res = await api.passwords();
        const list = Array.isArray(res?.passwords) ? res.passwords : [];
        if (list.length) {
          const match = list.find((pw) => pw && pw.ssid === ssid && pw.password);
          if (match) return match.password;
          /* Cache populated but no match -- no point in polling further. */
          return null;
        }
        /* First call returned an empty list -- the C5 has been kicked to
         * run `show_pass evil` and we have to wait for results. Tell the
         * user what's happening instead of letting the spinner hang. */
        if (attempt === 0 && monitorOpenRef.current) {
          pushMonitorLine('show_pass evil pending, waiting for cache...');
        }
      } catch (e) {
        /* keep polling */
      }
      await sleep(700);
    }
    return null;
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

    if ((attack === 'sae' || attack === 'gitm' || attack === 'rogue_gitm') && targets.length !== 1) {
      showToast(`${selectedAttack.label} requires exactly 1 target`, 'warning');
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

    /* GITM and Rogue GITM are two different attacks (capture_gateway start vs
     * start_rogue_gitm). For GITM the selected network is the upstream uplink
     * preselect; for Rogue GITM it's the victim to mirror. Their WiFi connect
     * and start command happen on their own dedicated pages. */
    if (attack === 'gitm') {
      route('/gitm');
      return;
    }

    if (attack === 'rogue_gitm') {
      route('/roguegitm');
      return;
    }

    const runner = {
      deauth: api.deauth,
      handshake: api.handshake,
      sae: api.sae,
      sniffer: api.sniffer,
      mitm: api.mitm,
      /* Nmap is two-phase: first discover hosts, then ask the user to pick
       * a target (or ALL = whole subnet) and a profile, then send
       * `start_nmap [level] [IP]`. The "runner" here just opens the setup
       * popup; the actual `api.nmap()` call happens in `pickNmapTarget`. */
      nmap: async () => openNmapSetup(),
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

        /* Open the monitor BEFORE the password lookup so the user sees
         * what's happening (otherwise the UI freezes silently for up to
         * ~3 s while we poll show_pass evil results). */
        openMonitor(attack, `${selectedAttack.label} Serial`);
        pushMonitorLine(`Looking up cached password for ${target.ssid} (show_pass evil)...`);

        // Bug 3: try the show_pass evil cache first. If we already know
        // the password for this SSID, skip the popup and connect+attack
        // automatically.
        const cachedPw = await lookupCachedPassword(target.ssid);
        if (cachedPw) {
          pushMonitorLine('Cached password found, auto-connecting');
          await connectAndLaunchPending(cachedPw);
          return;
        }

        pushMonitorLine('No cached password, prompting user for credentials');
        /* Close monitor before showing the popup -- otherwise the popup
         * stacks on top of the monitor and the user has two overlapping
         * dialogs. The breadcrumbs are preserved if connectAndLaunchPending
         * is later called -- it re-opens with a fresh log. */
        closeMonitor();

        setConnectSsid(target.ssid);
        setConnectVendor(target.vendor || '');
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
      setAttackRunning(true);
      pushLine(`${attack} started`);
      if (attack === 'sniffer') route('/sniffer');
    } else {
      showToast(res.error || 'Failed to start attack', 'error');
    }
  }

  async function stopAndClosePopup() {
    await api.stop();
    setAttackRunning(false);
    setConnectOpen(false);
    closeMonitor();
    pendingRef.current = null;
    setConnectBusy(false);
    connectOutcomeRef.current = { ok: false, error: 'stopped' };
    showToast('Stop sent', 'warning');
  }

  async function stopAll() {
    await api.stop();
    setAttackRunning(false);
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
        onToggle={attackLive ? () => {} : toggleNetwork}
        onToggleAll={attackLive ? () => {} : setAllNetworks}
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
              disabled={attackLive}
            >
              {opt.label}
              {!opt.available ? <span class="chip-mini">Soon</span> : null}
            </button>
          ))}
        </div>
        {attack === 'nmap' && !attackLive ? (
          <div class="alert info">
            After launch you'll pick a profile (quick / medium / heavy) and a host
            (or ALL = full subnet) once host discovery finishes.
          </div>
        ) : null}
        {attackLive ? (
          <>
            <div class="alert info">
              Attack running on {st.selected.size} selected network(s). Selection is
              locked — press Stop to change targets.
            </div>
            <button class="btn btn-danger" onClick={stopAll}>
              Stop {selectedAttack?.label}
            </button>
          </>
        ) : (
          <button class="btn btn-primary" onClick={launchAttack} disabled={!st.selected.size || scanning}>
            Launch {selectedAttack?.label}
          </button>
        )}
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
              {connectVendor ? <span class="badge">{connectVendor}</span> : null}
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
              <button class="btn btn-info" disabled={connectBusy} onClick={() => connectAndLaunchPending()}>
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
              <div>
                <div class="section-head">
                  <h3 class="section-title">Discovered Hosts</h3>
                  {arpBanTarget ? (
                    <span class="badge ok">Poisoning {arpBanTarget.ip}</span>
                  ) : (
                    <span class="badge">{arpRows.length} host{arpRows.length === 1 ? '' : 's'}</span>
                  )}
                </div>
                {!arpRows.length ? (
                  <div class="mini-serial-line empty">No hosts discovered yet</div>
                ) : (
                  <div class="attack-picker">
                    {arpRows.map((row) => {
                      const isTarget = arpBanTarget && arpBanTarget.mac === row.mac;
                      return (
                        <button
                          key={`${row.ip}-${row.mac}`}
                          class={`attack-chip ${isTarget ? 'active' : ''}`}
                          disabled={arpBanBusy || (arpBanTarget && !isTarget)}
                          onClick={() => banArpHost(row)}
                          title="arp_ban this host"
                        >
                          <strong>{row.ip}</strong>
                          <span class="chip-mini">{row.mac}</span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            ) : null}

            {monitorAttack === 'nmap' ? (
              <div class="nmap-results">
                <div class="nmap-summary">
                  {nmapStats.level ? (
                    <span class="badge info">profile: {nmapStats.level}</span>
                  ) : null}
                  {nmapStats.totalHosts ? (
                    <span class="badge">hosts: {nmapStats.totalHosts}</span>
                  ) : null}
                  {nmapStats.scanningHost ? (
                    <span class="badge ok">
                      <span class="spinner" /> {nmapStats.scanningHost}
                      {nmapStats.portTotal
                        ? ` (${nmapStats.portCurrent}/${nmapStats.portTotal})`
                        : ''}
                    </span>
                  ) : null}
                  {nmapStats.done && nmapStats.summary ? (
                    <span class="badge ok">{nmapStats.summary}</span>
                  ) : null}
                </div>
                {!nmapRows.length ? (
                  <div class="empty-state">
                    {nmapStats.done ? 'No hosts found.' : 'Waiting for hosts...'}
                  </div>
                ) : (
                  <div class="nmap-host-grid">
                    {nmapRows.map((row) => (
                      <div
                        key={row.ip}
                        class={`nmap-host-card ${row.scanning ? 'scanning' : ''} ${row.done ? 'done' : ''}`}
                      >
                        <div class="nmap-host-head">
                          <strong>{row.ip}</strong>
                          {row.scanning ? <span class="spinner" /> : null}
                          {row.done && !row.scanning ? (
                            <span class="badge ok">done</span>
                          ) : null}
                        </div>
                        <div class="nmap-host-mac">{row.mac || 'MAC unknown'}</div>
                        {row.ports.length ? (
                          <div class="nmap-port-row">
                            {row.ports.map((p) => (
                              <span class="nmap-port-chip" key={p.port} title={p.service}>
                                <strong>{p.port}</strong>
                                <span class="nmap-port-svc">{p.service}</span>
                              </span>
                            ))}
                          </div>
                        ) : row.noOpenPorts ? (
                          <div class="nmap-host-empty">No open ports</div>
                        ) : (
                          <div class="nmap-host-empty">Scanning...</div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
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

      {nmapSetupOpen ? (
        <div class="scan-modal-overlay">
          <section class="glass-card scan-modal scan-modal-compact">
            <div class="scan-modal-head">
              <h3 class="section-title">Nmap Setup</h3>
              <span class={`badge ${nmapSetupBusy ? '' : 'ok'}`}>
                {nmapSetupBusy ? 'Discovering hosts...' : `${arpRows.length} host${arpRows.length === 1 ? '' : 's'}`}
              </span>
            </div>

            <div class="field">
              <label class="field-label">Profile</label>
              <div class="attack-picker">
                {NMAP_LEVELS.map((level) => (
                  <button
                    key={level}
                    class={`attack-chip ${nmapLevel === level ? 'active' : ''}`}
                    onClick={() => setNmapLevel(level)}
                  >
                    {level}
                  </button>
                ))}
              </div>
            </div>

            <div class="field">
              <label class="field-label">Target</label>
              {nmapSetupBusy && !arpRows.length ? (
                <div class="empty-state">
                  <span class="spinner" /> Running list_hosts...
                </div>
              ) : null}

              {nmapSetupError ? (
                <div class="alert warn">{nmapSetupError}</div>
              ) : null}

              <div class="attack-picker">
                <button
                  class="attack-chip"
                  onClick={() => pickNmapTarget('')}
                  title="Scan whole subnet (no IP arg)"
                >
                  <strong>ALL</strong>
                  <span class="chip-mini">whole subnet</span>
                </button>
                {arpRows.map((row) => (
                  <button
                    key={`${row.ip}-${row.mac}`}
                    class="attack-chip"
                    onClick={() => pickNmapTarget(row.ip)}
                    title={`start_nmap ${nmapLevel} ${row.ip}`}
                  >
                    <strong>{row.ip}</strong>
                    <span class="chip-mini">{row.mac || 'icmp'}</span>
                  </button>
                ))}
              </div>
            </div>

            <div class="btn-row">
              <button class="btn btn-secondary" onClick={closeNmapSetup}>
                Cancel
              </button>
              <button
                class="btn btn-info"
                disabled={nmapSetupBusy}
                onClick={() => openNmapSetup()}
                title="Re-run list_hosts"
              >
                Rediscover
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </Layout>
  );
}
