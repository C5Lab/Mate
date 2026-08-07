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
  /* Firmware-orchestrated observer: Mate scans then auto-starts the sniffer,
   * so the launch survives the web disconnecting mid-scan (see cmd_do_observer_start). */
  observer:       ()          => post('/api/attack/observer'),
  snifferDog:     ()          => post('/api/attack/sniffer_dog'),
  beaconSpam:     (ssids)     => post('/api/attack/beacon_spam', { ssids }),
  karma:          (index)     => post('/api/attack/karma', { index }),
  mitm:           ()          => post('/api/attack/mitm'),
  nmap:           (level, ip) => post('/api/attack/nmap', { level, ip }),
  arp:            ()          => post('/api/attack/arp'),
  arpHosts:       ()          => get('/api/arp/hosts'),
  portalCaptures: ()          => get('/api/portal/captures'),
  snifferDogResults: ()       => get('/api/sniffer_dog/results'),
  nmapResults:    ()          => get('/api/nmap/results'),
  arpBan:         (mac, ip)   => post('/api/attack/arp_ban', { mac, ip: ip || '' }),
  btScan:         ()          => post('/api/attack/bt_scan'),
  btTrack:        (mac)       => post('/api/attack/bt_track', { mac }),
  airtag:         ()          => post('/api/attack/airtag'),
  btDevices:      ()          => get('/api/bt/devices'),
  wifiConnect:    (ssid, pw)  => post('/api/wifi/connect', { ssid, password: pw || '' }),
  wifiDisconnect: ()          => post('/api/wifi/disconnect'),
  snifferResults: ()          => get('/api/sniffer/results'),
  refreshSniffer: ()          => post('/api/sniffer/results'),
  probes:         ()          => get('/api/probes'),
  refreshProbes:  ()          => post('/api/probes'),
  stop:           ()          => post('/api/stop'),
  portals:        ()          => get('/api/portals'),
  selectPortal:   (index)     => post('/api/portal/select', { index }),
  passwords:      (kind = 'evil') => get('/api/passwords?kind=' + kind),
  handshakes:     ()          => get('/api/handshakes'),
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
  /* Mesh Recon (Zigbee/802.15.4). start begins the on-device capture; refresh
   * pulls one rotating snapshot query; results reads the parsed cache. */
  zigbeeStart:    ()          => post('/api/zigbee/start'),
  zigbeeRefresh:  ()          => post('/api/zigbee/refresh'),
  zigbeeResults:  ()          => get('/api/zigbee/results'),
  zigbeeClear:    ()          => post('/api/zigbee/clear'),
  wardriveConfig: ()          => get('/api/wardrive/config'),
  wardriveSetConfig: (cfg)    => post('/api/wardrive/config', cfg),
  wardriveFiles:  ()          => get('/api/wardrive/files'),
  wardriveUpload: (provider, mode, filename) =>
    post('/api/wardrive/upload', { provider, mode, filename: filename || '' }),
  gpsSetModule:   (module)    => post('/api/gps/module', { module }),
  gpsRaw:         (baud)      => post('/api/gps/raw', { baud: baud || 0 }),
  gpsRawStatus:   ()          => get('/api/gps/raw/status'),
  status:         ()          => get('/api/status'),
  serialTail:     (since)     => get(`/api/serial?since=${since || 0}`),
  dashboard:      ()          => get('/api/dashboard'),
  subghzListen:   (freq, raw) => post('/api/subghz/listen', { freq, raw: !!raw }),
  subghzJam:      (freq)      => post('/api/subghz/jam', { freq }),
  subghzStop:     ()          => post('/api/subghz/stop'),
  subghzTx:       (index, source = 'sd') => post('/api/subghz/tx', { index, source }),
  subghzTesla:    ()          => post('/api/subghz/tx', { preset: 'tesla' }),
  subghzSave:     (index)     => post('/api/subghz/save', { index }),
  subghzRssi:     ()          => get('/api/subghz/rssi'),
  subghzDelete:   (index)     => post('/api/subghz/delete', { index }),
  subghzClear:    ()          => post('/api/subghz/clear'),
  subghzExport:   ()          => post('/api/subghz/export'),
  subghzImport:   ()          => post('/api/subghz/import'),
  subghzListRefresh: (source = 'sd') => post('/api/subghz/list/refresh', { source }),
  subghzList:     ()          => get('/api/subghz/list'),
};
