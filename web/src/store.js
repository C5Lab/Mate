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
};

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

export function setQuickActions(actions) {
  const next = Array.isArray(actions) && actions.length === 3 ? actions : DEFAULT_QUICK_ACTIONS;
  try {
    localStorage.setItem(QUICK_ACTIONS_KEY, JSON.stringify(next));
  } catch (e) {
    /* ignore persistence errors */
  }
  setState({ quickActions: next });
}
