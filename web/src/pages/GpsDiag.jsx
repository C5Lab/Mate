import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { api } from '../api';
import { showToast } from '../components/Toast';

const MODULES = ['m5', 'atgm', 'external', 'cap'];
const BAUDS = [
  { v: 0, label: 'Module default' },
  { v: 9600, label: '9600' },
  { v: 38400, label: '38400' },
  { v: 57600, label: '57600' },
  { v: 115200, label: '115200' },
];

export function GpsDiag() {
  const [module, setModule] = useState('m5');
  const [baud, setBaud] = useState(0);
  /* Authoritative live state comes from the HTTP poll (the WS gps_nmea stream
   * is unreliable on the phone), so the feed fills and the Start/Stop buttons
   * reflect the true device state after a reload. */
  const [running, setRunning] = useState(false);
  const [lines, setLines] = useState([]);
  const [fix, setFix] = useState(null); // { quality, sats } | null
  const pollRef = useRef(null);

  /* Preselect the GPS module saved on the device (same source as the Wardrive
   * Settings page) so the dropdown matches without a manual change each visit. */
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await api.wardriveConfig();
        if (!cancelled && data && data.config && data.config.gps_module) {
          setModule(data.config.gps_module);
        }
      } catch (e) {
        /* keep default */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function poll() {
      try {
        const res = await api.gpsRawStatus();
        if (cancelled || !res || !res.ok) return;
        setRunning(!!res.running);
        if (Array.isArray(res.lines)) setLines(res.lines);
        setFix({ quality: String(res.quality ?? 0), sats: Number(res.sats) || 0 });
      } catch (e) {
        /* ignore transient poll errors */
      }
    }
    poll();
    pollRef.current = setInterval(poll, 1000);
    return () => {
      cancelled = true;
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  async function applyModule() {
    try {
      const res = await api.gpsSetModule(module);
      if (res && res.ok) showToast(`GPS module set to ${module}`, 'success');
      else showToast(res && res.error ? res.error : 'Failed to set module', 'error');
    } catch (e) {
      showToast('Failed to set module', 'error');
    }
  }

  async function start() {
    try {
      const res = await api.gpsRaw(Number(baud));
      if (res && res.ok) {
        setRunning(true);
        showToast('Reading raw NMEA...', 'info');
      } else {
        showToast(res && res.error ? res.error : 'Failed to start', 'error');
      }
    } catch (e) {
      showToast('Failed to start', 'error');
    }
  }

  async function stop() {
    try {
      await api.stop();
      setRunning(false);
      showToast('Stopped', 'info');
    } catch (e) {
      showToast('Failed to stop', 'error');
    }
  }

  const gga = fix ? { hasFix: fix.quality !== '' && fix.quality !== '0', quality: fix.quality, sats: fix.sats } : null;
  const feed = lines.length ? lines.join('\n') : '';

  return (
    <Layout
      title="GPS Diagnostics"
      subtitle="Stream raw NMEA from the device GPS to verify module, baud, and fix."
      back="/wardrive"
    >
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Module &amp; baud</h3>
          <span class={`badge ${running ? 'info' : 'warn'}`}>{running ? 'Reading' : 'Idle'}</span>
        </div>

        <div class="grid-two">
          <div class="field">
            <label class="field-label">GPS module (gps_set)</label>
            <select class="select" value={module} onChange={(e) => setModule(e.target.value)}>
              {MODULES.map((m) => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          </div>
          <div class="field">
            <label class="field-label">Raw baud override</label>
            <select class="select" value={String(baud)} onChange={(e) => setBaud(Number(e.target.value))}>
              {BAUDS.map((b) => (
                <option key={b.v} value={String(b.v)}>{b.label}</option>
              ))}
            </select>
          </div>
        </div>

        <div class="btn-row">
          <button class="btn btn-secondary" onClick={applyModule} disabled={running}>
            Set module
          </button>
          <button class="btn btn-primary" onClick={start} disabled={running}>
            Start raw NMEA
          </button>
          <button class="btn btn-secondary" onClick={stop} disabled={!running}>
            Stop
          </button>
        </div>

        <span class="section-note">
          Tip: for an AT6668/ATGM-based unit, try module <b>atgm</b> and baud <b>9600</b>. If the feed
          below shows readable $GxGGA/$GxRMC lines, the baud/pins are correct - a blank feed means wrong
          baud or wrong port.
        </span>
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Fix</h3>
          {gga ? (
            <span class={`badge ${gga.hasFix ? 'ok' : 'warn'}`}>
              {gga.hasFix ? `Fix (q${gga.quality}, ${gga.sats} sats)` : `No fix (${gga.sats} sats)`}
            </span>
          ) : (
            <span class="badge info">No GGA yet</span>
          )}
        </div>
        <span class="section-note">
          Quality 0 = no fix even if the module LED blinks. Sats &gt; 0 with quality 0 means it is still
          acquiring; quality 1+ means a usable fix.
        </span>
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Raw NMEA</h3>
          <span class="badge info">{lines.length}</span>
        </div>
        {feed ? (
          <textarea class="textarea" value={feed} readOnly rows={14} />
        ) : (
          <div class="empty-state">
            {running ? 'Waiting for NMEA sentences...' : 'Start raw NMEA to see live sentences.'}
          </div>
        )}
      </section>
    </Layout>
  );
}
