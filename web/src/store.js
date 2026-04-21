/**
 * Simple global store for shared state across pages.
 * Uses Preact signals pattern (manual subscription).
 */

let state = {
  networks: [],
  selected: new Set(),
  status: 'idle',
  wsConnected: false,
};

let listeners = [];

export function getState() {
  return state;
}

export function setState(partial) {
  state = { ...state, ...partial };
  listeners.forEach(fn => fn(state));
}

export function subscribe(fn) {
  listeners.push(fn);
  return () => { listeners = listeners.filter(l => l !== fn); };
}

export function toggleNetwork(idx) {
  const next = new Set(state.selected);
  if (next.has(idx)) next.delete(idx);
  else next.add(idx);
  setState({ selected: next });
}

export function setAllNetworks(selectAll) {
  const next = new Set();
  if (selectAll) state.networks.forEach(n => next.add(n.index));
  setState({ selected: next });
}
