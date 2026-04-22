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
  sdFreeGb: -1,
  sdTotalGb: -1,
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

export function setQuickActions(actions) {
  const next = Array.isArray(actions) && actions.length === 3 ? actions : DEFAULT_QUICK_ACTIONS;
  try {
    localStorage.setItem(QUICK_ACTIONS_KEY, JSON.stringify(next));
  } catch (e) {
    /* ignore persistence errors */
  }
  setState({ quickActions: next });
}
