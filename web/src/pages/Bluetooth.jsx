import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { showToast } from '../components/Toast';
import { api } from '../api';
import { wsAddListener } from '../ws';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* Map an RSSI value (dBm) to a 0-100 signal strength percentage. */
function rssiToPercent(rssi) {
  if (typeof rssi !== 'number' || !rssi) return 0;
  const clamped = Math.max(-100, Math.min(-40, rssi));
  return Math.round(((clamped + 100) / 60) * 100);
}

function rssiClass(rssi) {
  if (rssi >= -60) return 'ok';
  if (rssi >= -80) return 'info';
  return 'warn';
}

export function Bluetooth() {
  const [devices, setDevices] = useState([]);
  const [scanning, setScanning] = useState(false);

  const [trackMac, setTrackMac] = useState('');
  const [trackName, setTrackName] = useState('');
  const [trackRssi, setTrackRssi] = useState(null);
  const [trackHistory, setTrackHistory] = useState([]);

  const [airtagRunning, setAirtagRunning] = useState(false);
  const [airtagCounts, setAirtagCounts] = useState({ airtags: 0, smarttags: 0 });
  const [airtagLog, setAirtagLog] = useState([]);

  /* Refs so the WS listener (registered once) always sees current values. */
  const trackMacRef = useRef('');
  trackMacRef.current = trackMac;

  /* Safety timer: JanOS's BLE scan runs ~10s. If the bt_scan_complete frame
   * is ever lost, fall back to re-fetching the cached device list and clear
   * the spinner so it can't hang forever. */
  const scanTimerRef = useRef(null);
  const clearScanTimer = () => {
    if (scanTimerRef.current) {
      clearTimeout(scanTimerRef.current);
      scanTimerRef.current = null;
    }
  };

  useEffect(() => {
    /* Hydrate the device list from the firmware cache so it survives
     * navigation away and back while a scan's results are still cached. */
    api.btDevices().then((res) => {
      if (res && Array.isArray(res.devices) && res.devices.length) {
        setDevices(res.devices);
      }
    }).catch(() => {});

    const remove = wsAddListener((msg) => {
      if (msg.type === 'bt_device') {
        setDevices((prev) => {
          const next = prev.slice();
          const i = next.findIndex((d) => d.mac === msg.mac);
          const entry = {
            index: msg.index,
            mac: msg.mac,
            name: msg.name || '',
            rssi: msg.rssi,
          };
          if (i >= 0) next[i] = { ...next[i], ...entry };
          else next.push(entry);
          return next;
        });
      }

      if (msg.type === 'bt_scan_complete') {
        clearScanTimer();
        setScanning(false);
        showToast(
          `Scan done: ${msg.total} devices, ${msg.airtags} AirTags, ${msg.smarttags} SmartTags`,
          'success',
        );
      }

      if (msg.type === 'bt_track' && msg.mac === trackMacRef.current) {
        setTrackRssi(msg.rssi);
        if (msg.name) setTrackName(msg.name);
        setTrackHistory((prev) => [
          { ts: Date.now(), rssi: msg.rssi },
          ...prev,
        ].slice(0, 40));
      }

      if (msg.type === 'airtag_count') {
        setAirtagCounts({ airtags: msg.airtags, smarttags: msg.smarttags });
        setAirtagLog((prev) => [
          {
            id: `${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
            time: new Date().toLocaleTimeString(),
            airtags: msg.airtags,
            smarttags: msg.smarttags,
          },
          ...prev,
        ].slice(0, 50));
      }
    });

    return () => {
      remove();
      clearScanTimer();
    };
  }, []);

  async function startDeviceScan() {
    clearScanTimer();
    setDevices([]);
    setScanning(true);
    await api.stop().catch(() => {});
    await sleep(200);
    const res = await api.btScan().catch(() => ({ ok: false }));
    if (!res || !res.ok) {
      setScanning(false);
      showToast('Device is busy, try again', 'warning');
      return;
    }
    showToast('Scanning for Bluetooth devices (~10s)...', 'info');
    scanTimerRef.current = setTimeout(async () => {
      scanTimerRef.current = null;
      const snap = await api.btDevices().catch(() => null);
      if (snap && Array.isArray(snap.devices) && snap.devices.length) {
        setDevices(snap.devices);
      }
      setScanning(false);
    }, 13000);
  }

  async function startTracking(device) {
    setTrackMac(device.mac);
    setTrackName(device.name || '');
    setTrackRssi(device.rssi ?? null);
    setTrackHistory([]);
    setScanning(false);
    await api.stop().catch(() => {});
    await sleep(200);
    const res = await api.btTrack(device.mac).catch(() => ({ ok: false }));
    if (!res || !res.ok) {
      showToast('Could not start tracking', 'warning');
      setTrackMac('');
      return;
    }
    showToast(`Tracking ${device.name || device.mac}`, 'success');
  }

  async function stopTracking() {
    await api.stop().catch(() => {});
    setTrackMac('');
    setTrackName('');
    setTrackRssi(null);
    setTrackHistory([]);
  }

  async function startAirtag() {
    setAirtagRunning(true);
    setAirtagLog([]);
    setAirtagCounts({ airtags: 0, smarttags: 0 });
    await api.stop().catch(() => {});
    await sleep(200);
    const res = await api.airtag().catch(() => ({ ok: false }));
    if (!res || !res.ok) {
      setAirtagRunning(false);
      showToast('Device is busy, try again', 'warning');
      return;
    }
    showToast('AirTag scan started', 'info');
  }

  async function stopAirtag() {
    await api.stop().catch(() => {});
    setAirtagRunning(false);
  }

  const sortedDevices = devices
    .slice()
    .sort((a, b) => (b.rssi ?? -999) - (a.rssi ?? -999));

  return (
    <Layout
      title="Bluetooth"
      subtitle="Scan nearby Bluetooth devices, track one device's live RSSI, and sweep for AirTags."
      back="/"
    >
      {/* ---------- Device Scan ---------- */}
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Device Scan</h3>
          <span class="badge info">{devices.length} found</span>
        </div>
        <div class="btn-row">
          <button class="btn btn-success" onClick={startDeviceScan} disabled={scanning}>
            {scanning ? <span class="spinner" /> : null}
            {scanning ? 'Scanning...' : 'Start Device Scan'}
          </button>
        </div>

        {sortedDevices.length ? (
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>MAC</th>
                  <th>Name</th>
                  <th>RSSI</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {sortedDevices.map((d) => (
                  <tr key={d.mac}>
                    <td style="font-family: monospace;">{d.mac}</td>
                    <td>{d.name || '-'}</td>
                    <td>
                      <span class={`badge ${rssiClass(d.rssi)}`}>{d.rssi} dBm</span>
                    </td>
                    <td>
                      <button
                        class="btn btn-info"
                        onClick={() => startTracking(d)}
                        disabled={trackMac === d.mac}
                      >
                        {trackMac === d.mac ? 'Tracking' : 'Track RSSI'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div class="empty-state">
            {scanning ? 'Scanning for devices...' : 'No Bluetooth devices yet. Start a scan.'}
          </div>
        )}
      </section>

      {/* ---------- RSSI Tracker ---------- */}
      {trackMac ? (
        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">RSSI Tracker</h3>
            <span class="badge warn">Live</span>
          </div>

          <div class="stats-grid" style="grid-template-columns: repeat(2, minmax(0, 1fr));">
            <article class="stat-card">
              <div class="stat-label">Device</div>
              <div class="stat-value" style="font-size: 1rem;">
                {trackName || trackMac}
              </div>
              <div class="section-note" style="font-family: monospace;">{trackMac}</div>
            </article>
            <article class="stat-card">
              <div class="stat-label">Current RSSI</div>
              <div class="stat-value">
                {trackRssi === null ? '--' : `${trackRssi} dBm`}
              </div>
            </article>
          </div>

          <div style="margin: 14px 0;">
            <div
              style="height: 14px; border-radius: 8px; background: rgba(255,255,255,0.08); overflow: hidden;"
            >
              <div
                style={`height: 100%; width: ${rssiToPercent(trackRssi)}%; transition: width 0.3s ease; background: linear-gradient(90deg, #ef4444, #f59e0b, #22c55e);`}
              />
            </div>
            <div class="section-note" style="margin-top: 6px;">
              Signal strength {rssiToPercent(trackRssi)}% - move closer to increase.
            </div>
          </div>

          <div class="btn-row">
            <button class="btn btn-danger" onClick={stopTracking}>
              Stop Tracking
            </button>
          </div>

          {trackHistory.length ? (
            <div class="table-wrap" style="margin-top: 12px; max-height: 220px; overflow-y: auto;">
              <table class="table">
                <thead>
                  <tr>
                    <th>RSSI</th>
                    <th>Signal</th>
                  </tr>
                </thead>
                <tbody>
                  {trackHistory.map((h, i) => (
                    <tr key={`${h.ts}-${i}`}>
                      <td>{h.rssi} dBm</td>
                      <td>
                        <div
                          style={`height: 8px; border-radius: 4px; width: ${rssiToPercent(h.rssi)}%; background: var(--accent, #38bdf8);`}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </section>
      ) : null}

      {/* ---------- AirTag Scan ---------- */}
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">AirTag Scan</h3>
          <span class="badge info">{airtagRunning ? 'Live' : 'Idle'}</span>
        </div>

        <div class="stats-grid" style="grid-template-columns: repeat(2, minmax(0, 1fr));">
          <article class="stat-card">
            <div class="stat-label">AirTags</div>
            <div class="stat-value">{airtagCounts.airtags}</div>
          </article>
          <article class="stat-card">
            <div class="stat-label">SmartTags</div>
            <div class="stat-value">{airtagCounts.smarttags}</div>
          </article>
        </div>

        <div class="btn-row">
          {airtagRunning ? (
            <button class="btn btn-danger" onClick={stopAirtag}>
              Stop AirTag Scan
            </button>
          ) : (
            <button class="btn btn-info" onClick={startAirtag}>
              Start AirTag Scan
            </button>
          )}
        </div>

        {airtagLog.length ? (
          <div class="table-wrap" style="margin-top: 12px; max-height: 240px; overflow-y: auto;">
            <table class="table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>AirTags</th>
                  <th>SmartTags</th>
                </tr>
              </thead>
              <tbody>
                {airtagLog.map((row) => (
                  <tr key={row.id}>
                    <td>{row.time}</td>
                    <td>{row.airtags}</td>
                    <td>{row.smarttags}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div class="empty-state">
            {airtagRunning ? 'Waiting for AirTag counts (~30s interval)...' : 'No AirTag data yet.'}
          </div>
        )}
      </section>
    </Layout>
  );
}
