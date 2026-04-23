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
  blackout:       ()          => post('/api/attack/blackout'),
  evilTwin:       ()          => post('/api/attack/eviltwin'),
  portal:         (ssid)      => post('/api/attack/portal', { ssid }),
  rogueAP:        (ssid, pw)  => post('/api/attack/rogueap', { ssid, password: pw }),
  sae:            ()          => post('/api/attack/sae'),
  handshake:      ()          => post('/api/attack/handshake'),
  sniffer:        ()          => post('/api/attack/sniffer'),
  snifferNoscan:  ()          => post('/api/attack/sniffer_noscan'),
  karma:          (index)     => post('/api/attack/karma', { index }),
  mitm:           ()          => post('/api/attack/mitm'),
  nmap:           (level, ip) => post('/api/attack/nmap', { level, ip }),
  arp:            ()          => post('/api/attack/arp'),
  wifiConnect:    (ssid, pw)  => post('/api/wifi/connect', { ssid, password: pw || '' }),
  wifiDisconnect: ()          => post('/api/wifi/disconnect'),
  snifferResults: ()          => get('/api/sniffer/results'),
  refreshSniffer: ()          => post('/api/sniffer/results'),
  probes:         ()          => get('/api/probes'),
  refreshProbes:  ()          => post('/api/probes'),
  stop:           ()          => post('/api/stop'),
  portals:        ()          => get('/api/portals'),
  selectPortal:   (index)     => post('/api/portal/select', { index }),
  passwords:      ()          => get('/api/passwords'),
  wardriveLogs:   ()          => get('/api/wardrive/logs'),
  status:         ()          => get('/api/status'),
  dashboard:      ()          => get('/api/dashboard'),
};
