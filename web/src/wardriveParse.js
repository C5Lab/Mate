/**
 * Parse the raw wardrive/anti-surveillance UART lines that the firmware
 * forwards verbatim as `uart_line` WS events, and fold them into the global
 * store. Mirrors the ARP raw-line approach: doing it client-side avoids
 * fragile CSV parsing in C and keeps the firmware bridge minimal.
 */
import {
  getState,
  wardrivePushNet,
  wardrivePatch,
  antisurvPushFollower,
  antisurvPatch,
} from './store';

const MAC_RE = /^[0-9A-Fa-f:]{17}$/;

/* Two firmware CSV layouts share the same tail order but differ in field
 * count (verified from device logs):
 *   WIFI (11): MAC,SSID,[auth],FirstSeen,Ch,RSSI,Lat,Lon,Alt,Acc,WIFI
 *   BLE  (14): MAC,name,cap,FirstSeen,Ch,Freq,RSSI,Lat,Lon,Alt,Acc,RCOIs,MfgrId,BLE
 * SSID/name is the only field that may contain commas and a FIXED number of
 * fields follow it, so we index from the RIGHT (by type) to stay robust. */
export function parseWardriveCsv(line) {
  const parts = line.split(',');
  const n = parts.length;
  if (n < 8) return null;
  const type = parts[n - 1].trim();
  const mac = parts[0].trim();
  if (!MAC_RE.test(mac)) return null;

  let rssiI, latI, lonI, ssidEnd;
  if (type === 'WIFI')     { rssiI = n - 6; latI = n - 5; lonI = n - 4; ssidEnd = n - 9; }
  else if (type === 'BLE') { rssiI = n - 8; latI = n - 7; lonI = n - 6; ssidEnd = n - 12; }
  else return null;

  const rssi = parseInt(parts[rssiI], 10);
  const lat = parseFloat(parts[latI]);
  const lon = parseFloat(parts[lonI]);
  let ssid = parts.slice(1, Math.max(2, ssidEnd)).join(',').trim();
  if (ssid.length >= 2 && ssid[0] === '"' && ssid[ssid.length - 1] === '"') {
    ssid = ssid.slice(1, -1);
  }
  return {
    bssid: mac,
    ssid: ssid || (type === 'BLE' ? '[BLE]' : '[Hidden]'),
    rssi: Number.isFinite(rssi) ? rssi : 0,
    lat: Number.isFinite(lat) ? lat : 0,
    lon: Number.isFinite(lon) ? lon : 0,
    kind: type,
  };
}

/* "Wardrive promisc: 58 unique networks, 48 BT devices, 12 relogs,
 *  D-UCB best ch: 1 (34 visits), GPS: valid, sats: 5, dist: 1240.0m" */
export function parseWardriveStats(line) {
  if (!line.startsWith('Wardrive promisc:')) return null;
  const num = (re) => {
    const m = line.match(re);
    return m ? Number(m[1]) : null;
  };
  return {
    nets: num(/(\d+)\s+unique networks/) ?? 0,
    bt: num(/(\d+)\s+BT devices/) ?? 0,
    relogs: num(/(\d+)\s+relogs/) ?? 0,
    bestCh: num(/best ch:\s*(\d+)/) ?? 0,
    sats: num(/sats:\s*(\d+)/) ?? 0,
    dist: num(/dist:\s*([\d.]+)/) ?? 0,
    gpsValid: /GPS:\s*valid/i.test(line),
  };
}

/* "[FOLLOWER] MAC=AA:.. name="Smart Tag" type=SmartTag rssi=-60 seen=240s travel=2100m" */
export function parseFollower(line) {
  if (!line.includes('[FOLLOWER]')) return null;
  const mac = line.match(/MAC=([0-9A-Fa-f:]{17})/);
  if (!mac) return null;
  const name = line.match(/name="([^"]*)"/);
  const type = line.match(/type=(\S+)/);
  const rssi = line.match(/rssi=(-?\d+)/);
  const seen = line.match(/seen=(\d+)/);
  const travel = line.match(/travel=(\d+)/);
  return {
    mac: mac[1],
    name: name ? name[1] : '',
    type: type ? type[1] : '',
    rssi: rssi ? Number(rssi[1]) : 0,
    seen: seen ? Number(seen[1]) : 0,
    travel: travel ? Number(travel[1]) : 0,
  };
}

/**
 * Fold a single UART line into the store. Returns true if it was a
 * wardrive/anti-surveillance line (so callers may skip other handling).
 */
export function ingestWardriveLine(line) {
  // GPS fix lifecycle (drives the "waiting for fix" overlay)
  if (line.includes('GPS fix obtained') || line.includes('GPS fix recovered')) {
    wardrivePatch({ gps: 'fix' });
    return true;
  }
  // "Still waiting for GPS fix... (30 seconds)" -> elapsed seconds (no total)
  const waiting = line.match(/Still waiting for GPS fix\D*(\d+)\s*second/);
  if (waiting) {
    wardrivePatch({ gps: 'waiting', gpsCur: Number(waiting[1]), gpsTotal: 0 });
    return true;
  }
  // Initial "Waiting for GPS fix (no timeout...)" before any elapsed line
  if (line.includes('Waiting for GPS fix')) {
    wardrivePatch({ gps: 'waiting' });
    return true;
  }
  if (line.includes('GPS fix lost')) {
    wardrivePatch({ gps: 'lost' });
    return true;
  }
  if (line.includes('No GPS fix obtained')) {
    wardrivePatch({ gps: 'timeout' });
    return true;
  }

  // "Flushed 88 networks + 63 BT devices to /sdcard/lab/wardrives/w2.log"
  // Definitive proof of a GPS fix + gives the active log file name.
  const flushed = line.match(/Flushed\s+\d+\s+networks.*?to\s+(\S+)/);
  if (flushed) {
    const file = flushed[1].split('/').pop();
    wardrivePatch({ file, gps: 'fix' });
    return true;
  }

  const stats = parseWardriveStats(line);
  if (stats) {
    // A stats line with "GPS: valid" means the C5 has a fix even if we missed
    // the one-shot "GPS fix obtained" line.
    wardrivePatch(stats.gpsValid ? { stats, gps: 'fix' } : { stats });
    return true;
  }

  const follower = parseFollower(line);
  if (follower) {
    antisurvPushFollower(follower);
    return true;
  }

  const asStop = line.match(/Devices seen:\s*(\d+),\s*followers flagged:\s*(\d+)/);
  if (asStop) {
    antisurvPatch({ seen: Number(asStop[1]), flagged: Number(asStop[2]), running: false });
    return true;
  }

  // CSV sighting — only fold in while a run is active to avoid stray rows.
  if (getState().wardrive.running) {
    const net = parseWardriveCsv(line);
    if (net) {
      wardrivePushNet(net);
      // A logged row can only exist with a valid fix — self-heal the badge if
      // we somehow lost the 'fix' state (e.g. a late attack_started reset).
      if (getState().wardrive.gps !== 'fix') wardrivePatch({ gps: 'fix' });
      return true;
    }
  }
  return false;
}
