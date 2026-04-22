import { useMemo, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { getState } from '../store';
import { showToast } from '../components/Toast';

function buildWardriveRows(networks, lat, lon) {
  const baseLat = parseFloat(lat) || 0;
  const baseLon = parseFloat(lon) || 0;

  return networks.slice(0, 20).map((network, idx) => ({
    id: `${network.index}-${idx}`,
    ssid: network.ssid || '[Hidden]',
    bssid: network.bssid,
    rssi: network.rssi,
    lat: Number((baseLat + idx * 0.00011).toFixed(6)),
    lon: Number((baseLon + idx * 0.00009).toFixed(6)),
    ts: new Date().toISOString(),
  }));
}

export function Wardrive() {
  const st = getState();
  const [gpsMode, setGpsMode] = useState('manual');
  const [lat, setLat] = useState('52.2297');
  const [lon, setLon] = useState('21.0122');
  const [rows, setRows] = useState([]);

  function collectNow() {
    if (!st.networks.length) {
      showToast('Run WiFi Scan first to collect wardrive data', 'warning');
      return;
    }

    const nextRows = buildWardriveRows(st.networks, lat, lon);
    setRows(nextRows);
    showToast(`Wardrive snapshot created (${nextRows.length})`, 'success');
  }

  const mapReady = useMemo(
    () =>
      JSON.stringify(
        rows.map((row) => ({
          ssid: row.ssid,
          bssid: row.bssid,
          rssi: row.rssi,
          coordinates: [row.lat, row.lon],
          capturedAt: row.ts,
        })),
        null,
        2,
      ),
    [rows],
  );

  return (
    <Layout
      title="Wardrive"
      subtitle="Set GPS source, capture nearby networks, and export clean map-ready records."
      back="/"
    >
      <section class="glass-card card-body reveal">
        <div class="grid-two">
          <div class="field">
            <label class="field-label">GPS Mode</label>
            <select class="select" value={gpsMode} onChange={(e) => setGpsMode(e.target.value)}>
              <option value="manual">Manual Coordinates</option>
              <option value="external">External GPS (pending)</option>
            </select>
          </div>

          <div class="field">
            <label class="field-label">Last scanned networks</label>
            <input class="input" value={String(st.networks.length)} readOnly />
          </div>
        </div>

        <div class="grid-two">
          <div class="field">
            <label class="field-label">Latitude</label>
            <input class="input" value={lat} onInput={(e) => setLat(e.target.value)} />
          </div>
          <div class="field">
            <label class="field-label">Longitude</label>
            <input class="input" value={lon} onInput={(e) => setLon(e.target.value)} />
          </div>
        </div>

        <div class="btn-row">
          <button class="btn btn-primary" onClick={collectNow}>
            Capture Wardrive Snapshot
          </button>
          <button class="btn btn-secondary" onClick={() => setRows([])} disabled={!rows.length}>
            Clear Rows
          </button>
        </div>
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Collected Coordinates</h3>
          <span class="badge info">{rows.length}</span>
        </div>

        {!rows.length ? (
          <div class="empty-state">No wardrive entries yet.</div>
        ) : (
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>SSID</th>
                  <th>BSSID</th>
                  <th>RSSI</th>
                  <th>Coordinates</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id}>
                    <td>{row.ssid}</td>
                    <td>{row.bssid}</td>
                    <td>{row.rssi}</td>
                    <td>{row.lat}, {row.lon}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Map-Ready Data</h3>
          <span class="section-note">JSON export format</span>
        </div>
        <textarea class="textarea" value={mapReady} readOnly />
      </section>
    </Layout>
  );
}
