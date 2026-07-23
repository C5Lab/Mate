import { useEffect, useRef, useState } from 'preact/hooks';
import { route } from 'preact-router';
import { Layout } from '../components/Layout';
import { api } from '../api';
import { getState, wardriveReset, wardrivePatch, antisurvReset, antisurvPatch } from '../store';
import { showToast } from '../components/Toast';

const MEMCAP_OPTIONS = [10000, 20000, 40000, 80000, 120000, 200000];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const DEFAULT_FORM = {
  wifi24: true,
  wifi5: true,
  ble: true,
  channels: 'all',
  custom: '1:6:11:36',
  gps: '',
  wifiDelta: 5,
  bleDelta: 15,
  cooldown: 0,
  memCap: 40000,
  antisurv: 'med',
};

function bandsString(f) {
  const parts = [];
  if (f.wifi24) parts.push('wifi24');
  if (f.wifi5) parts.push('wifi5');
  if (f.ble) parts.push('ble');
  return parts.join(',');
}

export function Wardrive() {
  const st = getState();
  const wd = st.wardrive;
  const as = st.antisurv;

  const [form, setForm] = useState({ ...DEFAULT_FORM });
  const [loading, setLoading] = useState(false);
  const [applying, setApplying] = useState(false);
  const [trace, setTrace] = useState(false);
  const [blacklist, setBlacklist] = useState([]);
  const [newMac, setNewMac] = useState('');
  const busyRef = useRef(false);

  const set = (patch) => setForm((f) => ({ ...f, ...patch }));

  // Load the current config + blacklist from the C5 on mount. Sequential:
  // both are request/reply reads that need the device idle, so racing them
  // makes the second get a 409 "busy".
  useEffect(() => {
    (async () => {
      await loadConfig();
      await loadBlacklist();
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Poll live wardrive status over HTTP. The WebSocket drops frames under the
  // CSV flush flood, so this poll — not WS — is what reliably drives the GPS
  // badge and the stats tile.
  useEffect(() => {
    const id = setInterval(async () => {
      try {
        const s = await api.wardriveStatus();
        if (!s || !s.ok || !s.active) return;
        wardrivePatch({
          running: true,
          gps: s.gps_valid ? 'fix' : 'waiting',
          file: s.file || getState().wardrive.file,
          stats: {
            nets: s.nets, bt: s.bt, relogs: s.relogs,
            bestCh: s.best_ch, sats: s.sats, dist: s.dist,
            gpsValid: s.gps_valid,
          },
        });
      } catch (e) { /* ignore */ }
    }, 2000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function loadConfig() {
    if (busyRef.current) return;
    busyRef.current = true;
    setLoading(true);
    try {
      for (let i = 0; i < 25; i++) {
        const res = await api.wardriveConfigGet();
        if (res && res.config) {
          const c = res.config;
          const bands = (c.bands || '').split(',');
          set({
            wifi24: bands.includes('wifi24'),
            wifi5: bands.includes('wifi5'),
            ble: bands.includes('ble'),
            channels: c.channels || 'all',
            custom: c.custom || DEFAULT_FORM.custom,
            wifiDelta: c.wifi_delta ?? 5,
            bleDelta: c.ble_delta ?? 15,
            cooldown: c.cooldown ?? 0,
            memCap: c.mem_cap ?? 40000,
            antisurv: c.antisurv || 'med',
          });
          break;
        }
        if (!res || res.status !== 'loading') break;
        await sleep(350);
      }
    } catch (e) {
      showToast('Failed to load wardrive config', 'error');
    } finally {
      setLoading(false);
      busyRef.current = false;
    }
  }

  async function applyConfig() {
    setApplying(true);
    try {
      const cfg = {
        bands: bandsString(form) || 'wifi24',
        channels: form.channels,
        custom: form.custom,
        wifi_delta: Number(form.wifiDelta),
        ble_delta: Number(form.bleDelta),
        cooldown: Number(form.cooldown),
        mem_cap: Number(form.memCap),
        antisurv: form.antisurv,
      };
      if (form.gps) cfg.gps = form.gps;
      const res = await api.wardriveConfigSet(cfg);
      if (res && res.ok) showToast('Config applied (saved to NVS)', 'success');
      else showToast(res?.error === 'busy' ? 'Device busy' : 'Apply failed', 'error');
    } catch (e) {
      showToast('Apply failed', 'error');
    } finally {
      setApplying(false);
    }
  }

  async function startRun() {
    const res = await api.wardriveStart(trace);
    if (res && res.ok) {
      wardriveReset({ running: true, trace, gps: 'waiting' }); // optimistic; poll reconciles
      showToast(`Wardrive started${trace ? ' (+KML)' : ''}`, 'success');
    } else {
      showToast(res?.error === 'busy' ? 'Device busy' : 'Start failed', 'error');
    }
  }

  async function stopRun() {
    await api.stop();
    wardrivePatch({ running: false, gps: 'idle' });
    antisurvPatch({ running: false });
    showToast('Stopped', 'info');
  }

  async function startAntisurv() {
    const res = await api.wardriveAntisurv();
    if (res && res.ok) {
      antisurvReset({ running: true });
      showToast('Anti-surveillance started', 'success');
    } else {
      showToast(res?.error === 'busy' ? 'Device busy' : 'Start failed', 'error');
    }
  }

  async function loadBlacklist() {
    try {
      for (let i = 0; i < 20; i++) {
        const res = await api.wardriveBlacklistGet();
        if (res && Array.isArray(res.macs)) {
          setBlacklist(res.macs);
          break;
        }
        if (!res || res.status !== 'loading') break;
        await sleep(300);
      }
    } catch (e) {
      /* ignore */
    }
  }

  async function editBlacklist(action, mac) {
    const res = await api.wardriveBlacklistEdit(action, mac);
    if (res && res.ok) {
      showToast(`Blacklist ${action} ok`, 'success');
      setTimeout(loadBlacklist, 400);
    } else {
      showToast('Blacklist edit failed (device busy?)', 'error');
    }
  }

  const running = wd.running;
  const gpsLabel = {
    idle: 'Idle',
    waiting: `Waiting for GPS fix${wd.gpsCur ? ` (${wd.gpsCur}s)` : '…'}`,
    fix: 'GPS fix',
    lost: 'GPS fix lost — paused',
    timeout: 'No GPS fix (timed out)',
  }[wd.gps] || wd.gps;

  return (
    <Layout
      title="Wardrive 2.0"
      subtitle="Configure the C5 engine, drive, and stream live sightings (WigleWifi-1.6)."
      back="/"
    >
      {/* ---------- Live control ---------- */}
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Scanner</h3>
          <span class={`badge ${running ? 'ok' : 'info'}`}>
            {running ? gpsLabel : 'Stopped'}
          </span>
        </div>

        <label class="field" style="flex-direction:row;align-items:center;gap:10px;">
          <input
            class="network-check"
            type="checkbox"
            checked={trace}
            disabled={running}
            onChange={(e) => setTrace(e.target.checked)}
          />
          <span class="field-label" style="margin:0;">Trace (write KML track)</span>
        </label>

        <div class="btn-row">
          {!running ? (
            <button class="btn btn-primary" onClick={startRun}>
              Start Wardrive
            </button>
          ) : (
            <button class="btn btn-danger" onClick={stopRun}>
              Stop
            </button>
          )}
        </div>

        {wd.stats && (
          <div class="stats-grid" style="margin-top:14px;">
            <Stat label="Networks" value={wd.stats.nets} />
            <Stat label="BT devices" value={wd.stats.bt} />
            <Stat label="Re-logs" value={wd.stats.relogs} />
            <Stat label="Best ch (D-UCB)" value={wd.stats.bestCh} />
            <Stat label="Satellites" value={wd.stats.sats} />
            <Stat label="Distance (m)" value={Math.round(wd.stats.dist)} />
          </div>
        )}

        {running && (wd.file || wd.stats) && (
          <div class="section-note" style="margin-top:10px;">
            {wd.file ? <>Logging to <strong>{wd.file}</strong></> : 'Waiting for first flush…'}
            {wd.stats && ` · GPS ${wd.stats.gpsValid ? 'valid' : 'invalid'} · sats ${wd.stats.sats}`}
          </div>
        )}
      </section>

      {/* ---------- Setup / config ---------- */}
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Setup</h3>
          <div class="btn-row" style="margin:0;">
            <button class="btn btn-soft" onClick={loadConfig} disabled={loading || running}>
              {loading ? 'Loading…' : 'Load current'}
            </button>
            <button class="btn btn-primary" onClick={applyConfig} disabled={applying || running}>
              {applying ? 'Applying…' : 'Apply'}
            </button>
          </div>
        </div>

        <div class="field">
          <label class="field-label">Bands</label>
          <div class="btn-row" style="margin:0;gap:18px;">
            <BandCheck label="2.4 GHz" checked={form.wifi24} onChange={(v) => set({ wifi24: v })} disabled={running} />
            <BandCheck label="5 GHz" checked={form.wifi5} onChange={(v) => set({ wifi5: v })} disabled={running} />
            <BandCheck label="BLE" checked={form.ble} onChange={(v) => set({ ble: v })} disabled={running} />
          </div>
        </div>

        <div class="grid-two">
          <div class="field">
            <label class="field-label">Channels</label>
            <select class="select" value={form.channels} disabled={running}
              onChange={(e) => set({ channels: e.target.value })}>
              <option value="popular">Popular (1/6/11 + 5G non-DFS)</option>
              <option value="all">All (+ secondary + DFS)</option>
              <option value="custom">Custom list</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label">GPS source</label>
            <select class="select" value={form.gps} disabled={running}
              onChange={(e) => set({ gps: e.target.value })}>
              <option value="">(unchanged)</option>
              <option value="m5">M5 GPS</option>
              <option value="atgm">ATGM336H</option>
              <option value="external">External feed</option>
              <option value="cap">Cap module</option>
            </select>
            <button class="btn btn-secondary" style="margin-top:8px" onClick={() => route('/gps/diag')}>
              GPS Diagnostics
            </button>
          </div>
        </div>

        {form.channels === 'custom' && (
          <div class="field">
            <label class="field-label">Custom channels (colon-separated, e.g. 1:6:11:36:149)</label>
            <input class="input" value={form.custom} disabled={running}
              onInput={(e) => set({ custom: e.target.value })} />
          </div>
        )}

        <div class="grid-two">
          <Slider label={`WiFi RSSI delta: ${form.wifiDelta === 0 ? 'once' : form.wifiDelta + ' dBm'}`}
            value={form.wifiDelta} min={0} max={50} disabled={running}
            onInput={(v) => set({ wifiDelta: v })} />
          <Slider label={`BLE RSSI delta: ${form.bleDelta === 0 ? 'once' : form.bleDelta + ' dBm'}`}
            value={form.bleDelta} min={0} max={50} disabled={running}
            onInput={(v) => set({ bleDelta: v })} />
        </div>

        <div class="grid-two">
          <Slider label={`Startup cooldown: ${form.cooldown} s`}
            value={form.cooldown} min={0} max={600} step={10} disabled={running}
            onInput={(v) => set({ cooldown: v })} />
          <div class="field">
            <label class="field-label">Memory cap (WiFi entries)</label>
            <select class="select" value={String(form.memCap)} disabled={running}
              onChange={(e) => set({ memCap: Number(e.target.value) })}>
              {MEMCAP_OPTIONS.map((m) => (
                <option key={m} value={String(m)}>{m.toLocaleString()}</option>
              ))}
            </select>
          </div>
        </div>
      </section>

      {/* ---------- Live sightings ---------- */}
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Live sightings</h3>
          <span class="badge info">{wd.nets.length}</span>
        </div>
        {!wd.nets.length ? (
          <div class="empty-state">No sightings yet. Start the engine and acquire a GPS fix.</div>
        ) : (
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr><th>SSID / Name</th><th>BSSID</th><th>RSSI</th><th>Type</th><th>Lat, Lon</th></tr>
              </thead>
              <tbody>
                {wd.nets.slice(0, 50).map((n, i) => (
                  <tr key={`${n.bssid}-${i}`}>
                    <td>{n.ssid}</td>
                    <td>{n.bssid}</td>
                    <td>{n.rssi}</td>
                    <td>{n.kind}</td>
                    <td>{n.lat.toFixed(6)}, {n.lon.toFixed(6)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* ---------- Blacklist ---------- */}
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">MAC Blacklist</h3>
          <span class="badge info">{blacklist.length}</span>
        </div>
        <div class="btn-row">
          <input class="input" placeholder="AA:BB:CC:DD:EE:FF" value={newMac}
            onInput={(e) => setNewMac(e.target.value)} style="flex:1;" />
          <button class="btn btn-soft" disabled={running || !newMac}
            onClick={() => { editBlacklist('add', newMac.trim()); setNewMac(''); }}>
            Add
          </button>
          <button class="btn btn-soft" onClick={loadBlacklist}>Reload</button>
          <button class="btn btn-danger" disabled={running || !blacklist.length}
            onClick={() => editBlacklist('clear', '')}>
            Clear
          </button>
        </div>
        {!blacklist.length ? (
          <div class="empty-state">Blacklist is empty.</div>
        ) : (
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>MAC</th><th></th></tr></thead>
              <tbody>
                {blacklist.map((m) => (
                  <tr key={m}>
                    <td>{m}</td>
                    <td style="text-align:right;">
                      <button class="btn btn-soft" disabled={running}
                        onClick={() => editBlacklist('remove', m)}>Remove</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* ---------- Anti-surveillance ---------- */}
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Anti-Surveillance</h3>
          <span class={`badge ${as.running ? 'ok' : 'info'}`}>
            {as.running ? 'Watching' : `Flagged: ${as.flagged}`}
          </span>
        </div>
        <div class="grid-two">
          <div class="field">
            <label class="field-label">Sensitivity</label>
            <select class="select" value={form.antisurv} disabled={as.running}
              onChange={(e) => set({ antisurv: e.target.value })}>
              <option value="low">Low (300s / 1000m)</option>
              <option value="med">Med (180s / 500m)</option>
              <option value="high">High (120s / 300m, incl. random MAC)</option>
            </select>
          </div>
          <div class="field" style="justify-content:flex-end;">
            <div class="btn-row" style="margin:0;">
              {!as.running ? (
                <button class="btn btn-primary" disabled={running} onClick={startAntisurv}>
                  Start
                </button>
              ) : (
                <button class="btn btn-danger" onClick={stopRun}>Stop</button>
              )}
            </div>
          </div>
        </div>
        {running && (
          <div class="alert" style="margin-top:10px;">
            Wardrive is running — stop it first (shared radio).
          </div>
        )}
        {!as.followers.length ? (
          <div class="empty-state">No followers flagged.</div>
        ) : (
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>MAC</th><th>Name</th><th>Type</th><th>RSSI</th><th>Seen</th><th>Travel</th></tr></thead>
              <tbody>
                {as.followers.map((f) => (
                  <tr key={f.mac} style="color:var(--red);">
                    <td>{f.mac}</td>
                    <td>{f.name || '—'}</td>
                    <td>{f.type || '—'}</td>
                    <td>{f.rssi}</td>
                    <td>{f.seen}s</td>
                    <td>{f.travel}m</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </Layout>
  );
}

function Stat({ label, value }) {
  return (
    <div class="stat-card">
      <div class="stat-value">{value}</div>
      <div class="stat-label">{label}</div>
    </div>
  );
}

function BandCheck({ label, checked, onChange, disabled }) {
  return (
    <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
      <input class="network-check" type="checkbox" checked={checked} disabled={disabled}
        onChange={(e) => onChange(e.target.checked)} />
      <span>{label}</span>
    </label>
  );
}

function Slider({ label, value, min, max, step = 1, onInput, disabled }) {
  return (
    <div class="field">
      <label class="field-label">{label}</label>
      <input type="range" min={min} max={max} step={step} value={value} disabled={disabled}
        style="width:100%;accent-color:var(--blue);"
        onInput={(e) => onInput(Number(e.target.value))} />
    </div>
  );
}
