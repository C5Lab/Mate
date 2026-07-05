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
  arpHosts:       ()          => get('/api/arp/hosts'),
  nmapResults:    ()          => get('/api/nmap/results'),
  arpBan:         (mac, ip)   => post('/api/attack/arp_ban', { mac, ip: ip || '' }),
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
  deauthDetect:   ()          => post('/api/deauth/detect'),
  deauthDetected: ()          => get('/api/deauth/detected'),
  wardriveConfigGet:  ()      => get('/api/wardrive/config'),
  wardriveConfigSet:  (cfg)   => post('/api/wardrive/config', cfg),
  wardriveStart:      (trace) => post('/api/wardrive/start', { trace: !!trace }),
  wardriveStatus:     ()      => get('/api/wardrive/status'),
  wardriveAntisurv:   ()      => post('/api/wardrive/antisurv'),
  wardriveBlacklistGet: ()    => get('/api/wardrive/blacklist'),
  wardriveBlacklistEdit: (action, mac) =>
                                 post('/api/wardrive/blacklist', { action, mac: mac || '' }),
  status:         ()          => get('/api/status'),
  serialTail:     (since)     => get(`/api/serial?since=${since || 0}`),
  dashboard:      ()          => get('/api/dashboard'),
  subghzListen:   (freq, raw) => post('/api/subghz/listen', { freq, raw: !!raw }),
  subghzJam:      (freq)      => post('/api/subghz/jam', { freq }),
  subghzTx:       (index)     => post('/api/subghz/tx', { index }),
  subghzTesla:    ()          => post('/api/subghz/tx', { preset: 'tesla' }),
  subghzDelete:   (index)     => post('/api/subghz/delete', { index }),
  subghzClear:    ()          => post('/api/subghz/clear'),
  subghzExport:   ()          => post('/api/subghz/export'),
  subghzImport:   ()          => post('/api/subghz/import'),
  subghzListRefresh: ()       => post('/api/subghz/list/refresh'),
  subghzList:     ()          => get('/api/subghz/list'),
};
