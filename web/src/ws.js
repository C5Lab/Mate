/**
 * WebSocket client with auto-reconnect and event dispatching.
 * Listeners receive parsed JSON messages.
 */

let socket = null;
let listeners = [];
let reconnectTimer = null;

const WS_URL = `ws://${location.host}/ws`;

function connect() {
  if (socket && socket.readyState <= 1) return;

  socket = new WebSocket(WS_URL);

  socket.onopen = () => {
    console.log('[WS] connected');
    dispatch({ type: 'ws_connected' });
  };

  socket.onclose = () => {
    console.log('[WS] disconnected, reconnecting in 2s');
    dispatch({ type: 'ws_disconnected' });
    scheduleReconnect();
  };

  socket.onerror = () => {
    socket.close();
  };

  socket.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      dispatch(msg);
    } catch (e) {
      console.warn('[WS] bad message:', ev.data);
    }
  };
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connect();
  }, 2000);
}

function dispatch(msg) {
  for (const fn of listeners) {
    try { fn(msg); } catch (e) { console.error('[WS] listener error:', e); }
  }
}

export function wsConnect() {
  connect();
}

export function wsAddListener(fn) {
  listeners.push(fn);
  return () => {
    listeners = listeners.filter(l => l !== fn);
  };
}

export function wsIsConnected() {
  return socket && socket.readyState === 1;
}
