const BASE = '';

async function post(url, body) {
  const res = await fetch(BASE + url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  return res.json();
}

async function get(url) {
  const res = await fetch(BASE + url);
  return res.json();
}

export const api = {
  scan:           ()          => post('/api/scan'),
  scanResults:    ()          => get('/api/scan/results'),
  select:         (indices)   => post('/api/select', { indices }),
  deauth:         ()          => post('/api/attack/deauth'),
  evilTwin:       ()          => post('/api/attack/eviltwin'),
  rogueAP:        (ssid, pw)  => post('/api/attack/rogueap', { ssid, password: pw }),
  sae:            ()          => post('/api/attack/sae'),
  handshake:      ()          => post('/api/attack/handshake'),
  sniffer:        ()          => post('/api/attack/sniffer'),
  snifferResults: ()          => get('/api/sniffer/results'),
  refreshSniffer: ()          => post('/api/sniffer/results'),
  stop:           ()          => post('/api/stop'),
  portals:        ()          => get('/api/portals'),
  selectPortal:   (index)     => post('/api/portal/select', { index }),
  passwords:      ()          => get('/api/passwords'),
  status:         ()          => get('/api/status'),
};
