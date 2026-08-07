const QUICK_ACTIONS_KEY = 'mate.quickActions.v1';
const DEFAULT_QUICK_ACTIONS = ['scan', 'blackout', 'stop'];

function loadQuickActions() {
  try {
    const raw = localStorage.getItem(QUICK_ACTIONS_KEY);
    if (!raw) return DEFAULT_QUICK_ACTIONS;
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length !== 3) return DEFAULT_QUICK_ACTIONS;
    return parsed;
  } catch (e) {
    return DEFAULT_QUICK_ACTIONS;
  }
}

let state = {
  deviceName: 'JanOS Control',
  powerSource: 'USB',
  wsConnected: false,
  c5Connected: false,
  apClients: 0,
  staConnected: false,
  staSsid: '',
  heapFree: 0,
  heapInternal: 0,
  status: 'idle',
  /* Global foreground-attack lock. Mirrors whether the Monster is running a
   * Scan-page attack (deauth/handshake/mitm/nmap/arp/…). Kept here — not in the
   * Scan component's local state — so it survives navigation, WS reconnects and
   * the disconnect→return case: the /api/status poll reconciles it against the
   * authoritative device FSM, so the Scan lock can no longer stay stuck on
   * "Attack running" after the Monster has actually gone idle.
   * `attackRunningSince` timestamps the optimistic launch so the poll won't
   * clear a freshly-armed lock in the brief window before the device reports
   * the new state (see setAttackRunning + the reconcile in app.jsx). */
  attackRunning: false,
  attackRunningSince: 0,
  networks: [],
  selected: new Set(),
  scanCount: 0,
  packetCount: 0,
  lastScanAt: null,
  quickActions: loadQuickActions(),
  handshakeCount: 0,
  handshakeLoading: false,
  gpsFix: false,
  gpsLat: 0,
  gpsLon: 0,
  /* Live wardrive session state (driven by WS attack_started/stopped +
   * wardrive_status events). */
  wardriveRunning: false,
  wardriveSats: 0,
  wardriveDistance: 0,
  /* WiGLE/WDGWars upload session state. */
  wardriveUploadRunning: false,
  wardriveUploadProvider: '',
  wardriveUploadLast: '',
  wardriveUploadResult: null,
  wardriveUploadError: null,
  /* GPS raw NMEA diagnostics. */
  gpsRawRunning: false,
  gpsRawLines: [],
  /* SD presence from JanOS `sd_status`: 1 present, 0 absent, -1 unknown. */
  sdPresent: -1,
  /* Discovered hosts from `list_hosts` (ARP attack). Populated globally so
   * the data survives navigation and is captured even when the Scan ARP
   * monitor isn't open at the moment the lines arrive over UART. */
  arpHosts: [],
  arpHostsAt: 0,
  /* Wardrive 2.0 live state. Kept in the global store (like arpHosts) so the
   * stream survives navigation away from the Wardrive page and WS reconnects.
   * `nets` is a bounded ring buffer of the most recent CSV sightings. */
  wardrive: {
    running: false,
    trace: false,
    gps: 'idle', /* idle | waiting | fix | lost | timeout */
    gpsCur: 0,
    gpsTotal: 0,
    stats: null, /* { nets, bt, relogs, bestCh, sats, dist, gpsValid } */
    file: '',    /* active log file, e.g. "w2.log" */
    nets: [],
  },
  antisurv: {
    running: false,
    followers: [],
    seen: 0,
    flagged: 0,
  },
};

const WARDRIVE_NET_CAP = 200;

let listeners = [];

export function getState() {
  return state;
}

export function setState(partial) {
  state = { ...state, ...partial };
  listeners.forEach((fn) => fn(state));
}

export function subscribe(fn) {
  listeners.push(fn);
  return () => {
    listeners = listeners.filter((l) => l !== fn);
  };
}

export function toggleNetwork(idx) {
  const next = new Set(state.selected);
  if (next.has(idx)) next.delete(idx);
  else next.add(idx);
  setState({ selected: next });
}

export function setAllNetworks(selectAll) {
  const next = new Set();
  if (selectAll) state.networks.forEach((n) => next.add(n.index));
  setState({ selected: next });
}

/* Arm/disarm the global attack lock. Callers set it optimistically on launch
 * (true) and on Stop (false); the /api/status poll in app.jsx reconciles it
 * against the real device state afterwards. */
export function setAttackRunning(running) {
  setState({
    attackRunning: !!running,
    attackRunningSince: running ? Date.now() : 0,
  });
}

export function clearArpHosts() {
  setState({ arpHosts: [], arpHostsAt: 0 });
}

export function addArpHost(ip, mac) {
  if (!ip || !mac) return;
  const macUp = mac.toUpperCase();
  if (state.arpHosts.some((row) => row.ip === ip && row.mac === macUp)) return;
  setState({
    arpHosts: [...state.arpHosts, { ip, mac: macUp }],
    arpHostsAt: Date.now(),
  });
}

/* Replace the discovered-host list with an authoritative snapshot from the
 * device (delivered as a structured WS `arp_hosts` event or pulled via the
 * `/api/arp/hosts` poll). Hosts without a usable MAC (`icmp_only`) are kept
 * in the store so the UI can show them, but `arp_ban` callers will skip
 * them because the MAC is empty. */
export function setArpHosts(hosts, atMs) {
  const list = Array.isArray(hosts) ? hosts : [];
  const next = list
    .map((row) => ({
      ip: String(row?.ip || ''),
      mac: String(row?.mac || '').toUpperCase(),
      icmp_only: !!row?.icmp_only,
    }))
    .filter((row) => row.ip);
  setState({
    arpHosts: next,
    arpHostsAt: typeof atMs === 'number' && atMs > 0 ? atMs : Date.now(),
  });
}

/* ---------- Wardrive 2.0 live state ---------- */

export function wardriveReset(patch = {}) {
  setState({
    wardrive: {
      running: false,
      trace: false,
      gps: 'idle',
      gpsCur: 0,
      gpsTotal: 0,
      stats: null,
      file: '',
      nets: [],
      ...patch,
    },
  });
}

export function wardrivePatch(patch) {
  setState({ wardrive: { ...state.wardrive, ...patch } });
}

export function wardrivePushNet(net) {
  if (!net || !net.bssid) return;
  const nets = [net, ...state.wardrive.nets];
  if (nets.length > WARDRIVE_NET_CAP) nets.length = WARDRIVE_NET_CAP;
  setState({ wardrive: { ...state.wardrive, nets } });
}

export function antisurvReset(patch = {}) {
  setState({
    antisurv: { running: false, followers: [], seen: 0, flagged: 0, ...patch },
  });
}

export function antisurvPatch(patch) {
  setState({ antisurv: { ...state.antisurv, ...patch } });
}

export function antisurvPushFollower(f) {
  if (!f || !f.mac) return;
  const macUp = f.mac.toUpperCase();
  const existing = state.antisurv.followers.find((x) => x.mac === macUp);
  const followers = existing
    ? state.antisurv.followers.map((x) => (x.mac === macUp ? { ...x, ...f, mac: macUp } : x))
    : [{ ...f, mac: macUp }, ...state.antisurv.followers];
  setState({
    antisurv: {
      ...state.antisurv,
      followers,
      flagged: existing ? state.antisurv.flagged : state.antisurv.flagged + 1,
    },
  });
}

export function setQuickActions(actions) {
  const next = Array.isArray(actions) && actions.length === 3 ? actions : DEFAULT_QUICK_ACTIONS;
  try {
    localStorage.setItem(QUICK_ACTIONS_KEY, JSON.stringify(next));
  } catch (e) {
    /* ignore persistence errors */
  }
  setState({ quickActions: next });
}
