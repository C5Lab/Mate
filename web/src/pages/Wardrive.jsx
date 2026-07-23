import { useEffect, useRef, useState } from 'preact/hooks';
import { route } from 'preact-router';
import { Layout } from '../components/Layout';
import { getState } from '../store';
import { api } from '../api';
import { showToast } from '../components/Toast';

const MEM_CAP_OPTIONS = [10000, 20000, 40000, 80000, 120000, 200000];
const GPS_MODULES = ['m5', 'atgm', 'external', 'cap'];

const DEFAULT_CFG = {
  wifi24: true,
  wifi5: true,
  ble: true,
  channels: 'all',
  customChannels: '',
  wifiRssiDelta: 5,
  bleRssiDelta: 15,
  cooldown: 0,
  memCap: 40000,
  antisurv: 'med',
  gpsModule: 'm5',
};

function bandsToString(cfg) {
  const parts = [];
  if (cfg.wifi24) parts.push('wifi24');
  if (cfg.wifi5) parts.push('wifi5');
  if (cfg.ble) parts.push('ble');
  return parts.join(',');
}

function parseConfig(raw) {
  const bands = String(raw.bands || '');
  const nearest = MEM_CAP_OPTIONS.reduce(
    (best, v) => (Math.abs(v - (raw.mem_cap || 0)) < Math.abs(best - (raw.mem_cap || 0)) ? v : best),
    40000,
  );
  return {
    wifi24: bands.includes('wifi24'),
    wifi5: bands.includes('wifi5'),
    ble: bands.includes('ble'),
    channels: raw.channels || 'all',
    customChannels: raw.custom_channels || '',
    wifiRssiDelta: Number.isFinite(raw.wifi_rssi_delta) ? raw.wifi_rssi_delta : 5,
    bleRssiDelta: Number.isFinite(raw.ble_rssi_delta) ? raw.ble_rssi_delta : 15,
    cooldown: Number.isFinite(raw.startup_cooldown) ? raw.startup_cooldown : 0,
    memCap: nearest,
    antisurv: raw.antisurv || 'med',
    gpsModule: raw.gps_module || 'm5',
  };
}

function fmtDistance(m) {
  const d = Number(m) || 0;
  return d < 1000 ? `${d.toFixed(1)} m` : `${(d / 1000).toFixed(2)} km`;
}

export function Wardrive() {
  const st = getState();
  const [cfg, setCfg] = useState(DEFAULT_CFG);
  const [trace, setTrace] = useState(true);
  const [applying, setApplying] = useState(false);

  /* Settings are hidden by default and only pulled from the C5 the first time
   * the user expands the panel. */
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const settingsLoadedRef = useRef(false);
  const cfgPollRef = useRef(null);

  /* Live session state comes from the HTTP poll (the WS wardrive_status +
   * raw CSV rows are unreliable on the phone), matching how the GPS
   * coordinates already reach the UI via the dashboard poll. */
  const [running, setRunning] = useState(false);
  const [live, setLive] = useState({ sats: 0, dist: 0, unique: 0, relogs: 0 });
  const [nets, setNets] = useState([]);
  const statusPollRef = useRef(null);

  function set(key, value) {
    setCfg((c) => ({ ...c, [key]: value }));
  }

  async function loadConfig() {
    setLoading(true);
    try {
      const data = await api.wardriveConfig();
      if (data && data.config) {
        setCfg(parseConfig(data.config));
        setLoading(false);
        return true;
      }
    } catch (e) {
      /* keep polling / defaults */
    }
    return false;
  }

  useEffect(() => {
    let cancelled = false;
    async function poll() {
      try {
        const res = await api.wardriveStatus();
        if (cancelled || !res || !res.ok) return;
        setRunning(!!res.running);
        setLive({
          sats: Number(res.sats) || 0,
          dist: Number(res.dist) || 0,
          unique: Number(res.unique) || 0,
          relogs: Number(res.relogs) || 0,
        });
        if (Array.isArray(res.networks)) setNets(res.networks);
      } catch (e) {
        /* ignore transient poll errors */
      }
    }
    poll();
    statusPollRef.current = setInterval(poll, 1500);
    return () => {
      cancelled = true;
      if (statusPollRef.current) clearInterval(statusPollRef.current);
      if (cfgPollRef.current) clearInterval(cfgPollRef.current);
    };
  }, []);

  function toggleSettings() {
    const next = !settingsOpen;
    setSettingsOpen(next);
    if (next && !settingsLoadedRef.current) {
      settingsLoadedRef.current = true;
      (async () => {
        const done = await loadConfig();
        if (!done) {
          /* Config query still loading on the device; poll until it lands. */
          cfgPollRef.current = setInterval(async () => {
            const ok = await loadConfig();
            if (ok && cfgPollRef.current) {
              clearInterval(cfgPollRef.current);
              cfgPollRef.current = null;
            }
          }, 1500);
        }
      })();
    }
  }

  async function applyConfig() {
    if (!cfg.wifi24 && !cfg.wifi5 && !cfg.ble) {
      showToast('Select at least one band', 'warning');
      return;
    }
    setApplying(true);
    try {
      const res = await api.wardriveSetConfig({
        bands: bandsToString(cfg),
        channels: cfg.channels,
        custom_channels: cfg.customChannels,
        wifi_rssi_delta: Number(cfg.wifiRssiDelta),
        ble_rssi_delta: Number(cfg.bleRssiDelta),
        startup_cooldown: Number(cfg.cooldown),
        mem_cap: Number(cfg.memCap),
        antisurv: cfg.antisurv,
        gps_module: cfg.gpsModule,
      });
      if (res && res.ok) showToast('Wardrive settings applied (saved to device)', 'success');
      else showToast(res && res.error ? res.error : 'Failed to apply settings', 'error');
    } catch (e) {
      showToast('Failed to apply settings', 'error');
    } finally {
      setApplying(false);
    }
  }

  async function start() {
    try {
      const res = await api.wardriveStart(trace);
      if (res && res.ok) {
        setRunning(true);
        showToast(`Wardrive started${trace ? ' (KML trace)' : ''}`, 'success');
      } else {
        showToast(res && res.error ? res.error : 'Failed to start wardrive', 'error');
      }
    } catch (e) {
      showToast('Failed to start wardrive', 'error');
    }
  }

  async function stop() {
    try {
      await api.stop();
      setRunning(false);
      showToast('Wardrive stopped', 'info');
    } catch (e) {
      showToast('Failed to stop', 'error');
    }
  }

  return (
    <Layout
      title="Wardrive"
      subtitle="Configure the scan, then start a GPS-logged wardrive on the device."
      back="/"
    >
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Session</h3>
          <span class={`badge ${running ? 'ok' : 'info'}`}>{running ? 'Running' : 'Idle'}</span>
        </div>

        <div class="field">
          <label class="field-label">
            <input
              type="checkbox"
              class="network-check"
              checked={trace}
              disabled={running}
              onChange={(e) => setTrace(e.target.checked)}
            />
            {' '}Trace (KML track)
          </label>
          <span class="section-note">
            On: start_wardrive_promisc_trace &middot; Off: start_wardrive_promisc
          </span>
        </div>

        <div class="grid-two">
          <div class="field">
            <label class="field-label">GPS fix</label>
            <input
              class="input"
              value={
                st.gpsFix
                  ? `${st.gpsLat.toFixed(6)}, ${st.gpsLon.toFixed(6)}`
                  : 'No fix yet'
              }
              readOnly
            />
          </div>
          <div class="field">
            <label class="field-label">Live</label>
            <input
              class="input"
              value={`SAT: ${live.sats}   ${fmtDistance(live.dist)}   ${live.unique} nets`}
              readOnly
            />
          </div>
        </div>

        <div class="btn-row">
          <button class="btn btn-primary" onClick={start} disabled={running}>
            Start
          </button>
          <button class="btn btn-secondary" onClick={stop} disabled={!running}>
            Stop
          </button>
          <button class="btn btn-secondary" onClick={() => route('/wardrive/upload')} disabled={running}>
            Upload logs
          </button>
          <button class="btn btn-secondary" onClick={() => route('/gps/diag')} disabled={running}>
            GPS diagnostics
          </button>
        </div>
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Networks</h3>
          <span class="badge info">{nets.length}</span>
        </div>
        {nets.length > 0 ? (
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr><th>SSID</th><th>BSSID</th><th>Sec</th><th>CH</th><th>RSSI</th></tr>
              </thead>
              <tbody>
                {nets.map((n, i) => (
                  <tr key={`${n.mac}:${i}`}>
                    <td>{n.ssid || '(hidden)'}</td>
                    <td>{n.mac}</td>
                    <td>{String(n.sec || '').replace(/[[\]]/g, '')}</td>
                    <td>{n.ch}</td>
                    <td>{n.rssi}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div class="empty-state">
            {running ? 'Waiting for networks...' : 'Start a wardrive to see live networks.'}
          </div>
        )}
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Settings</h3>
          <button class="soft-btn" onClick={toggleSettings}>
            {settingsOpen ? 'Hide' : 'Show'}
          </button>
        </div>

        {settingsOpen ? (
          <>
            <span class="section-note">
              {loading ? 'Loading from device...' : 'Saved on device NVS'}
            </span>

            <div class="field">
              <label class="field-label">Bands</label>
              <div class="btn-row">
                <label class="field-label">
                  <input
                    type="checkbox"
                    class="network-check"
                    checked={cfg.wifi24}
                    onChange={(e) => set('wifi24', e.target.checked)}
                  />
                  {' '}2.4 GHz
                </label>
                <label class="field-label">
                  <input
                    type="checkbox"
                    class="network-check"
                    checked={cfg.wifi5}
                    onChange={(e) => set('wifi5', e.target.checked)}
                  />
                  {' '}5 GHz
                </label>
                <label class="field-label">
                  <input
                    type="checkbox"
                    class="network-check"
                    checked={cfg.ble}
                    onChange={(e) => set('ble', e.target.checked)}
                  />
                  {' '}BLE
                </label>
              </div>
            </div>

            <div class="grid-two">
              <div class="field">
                <label class="field-label">Channels</label>
                <select
                  class="select"
                  value={cfg.channels}
                  onChange={(e) => set('channels', e.target.value)}
                >
                  <option value="popular">Popular</option>
                  <option value="all">All</option>
                  <option value="custom">Custom</option>
                </select>
              </div>
              <div class="field">
                <label class="field-label">Custom channels (e.g. 1:6:11:36)</label>
                <input
                  class="input"
                  value={cfg.customChannels}
                  disabled={cfg.channels !== 'custom'}
                  onInput={(e) => set('customChannels', e.target.value)}
                />
              </div>
            </div>

            <div class="grid-two">
              <div class="field">
                <label class="field-label">WiFi RSSI re-log delta: {cfg.wifiRssiDelta}</label>
                <input
                  type="range"
                  min="0"
                  max="50"
                  value={cfg.wifiRssiDelta}
                  onInput={(e) => set('wifiRssiDelta', Number(e.target.value))}
                />
              </div>
              <div class="field">
                <label class="field-label">BLE RSSI re-log delta: {cfg.bleRssiDelta}</label>
                <input
                  type="range"
                  min="0"
                  max="50"
                  value={cfg.bleRssiDelta}
                  onInput={(e) => set('bleRssiDelta', Number(e.target.value))}
                />
              </div>
            </div>

            <div class="grid-two">
              <div class="field">
                <label class="field-label">Startup cooldown: {cfg.cooldown} s</label>
                <input
                  type="range"
                  min="0"
                  max="600"
                  step="10"
                  value={cfg.cooldown}
                  onInput={(e) => set('cooldown', Number(e.target.value))}
                />
              </div>
              <div class="field">
                <label class="field-label">Memory cap</label>
                <select
                  class="select"
                  value={String(cfg.memCap)}
                  onChange={(e) => set('memCap', Number(e.target.value))}
                >
                  {MEM_CAP_OPTIONS.map((v) => (
                    <option key={v} value={String(v)}>
                      {v.toLocaleString()}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div class="grid-two">
              <div class="field">
                <label class="field-label">Anti-surveillance sensitivity</label>
                <select
                  class="select"
                  value={cfg.antisurv}
                  onChange={(e) => set('antisurv', e.target.value)}
                >
                  <option value="low">Low</option>
                  <option value="med">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
              <div class="field">
                <label class="field-label">GPS module</label>
                <select
                  class="select"
                  value={cfg.gpsModule}
                  onChange={(e) => set('gpsModule', e.target.value)}
                >
                  {GPS_MODULES.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div class="btn-row">
              <button class="btn btn-primary" onClick={applyConfig} disabled={applying || running}>
                {applying ? 'Applying...' : 'Apply Settings'}
              </button>
              <button class="btn btn-secondary" onClick={loadConfig} disabled={applying || running}>
                Reload
              </button>
            </div>
          </>
        ) : (
          <span class="section-note">Hidden. Show to load and edit the device config.</span>
        )}
      </section>
    </Layout>
  );
}
