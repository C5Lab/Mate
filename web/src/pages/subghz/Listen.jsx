import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../../components/Layout';
import { api } from '../../api';
import { showToast } from '../../components/Toast';
import { wsAddListener } from '../../ws';
import { fetchSubghzListAfterRefresh, mergeSubghzSignals } from '../../subghzUtil';

const WF_WIDTH = 320;
const WF_HEIGHT = 60;
const RSSI_MIN = -110;
const RSSI_MAX = -40;
// Waterfall scroll rate: one column every WF_TICK_MS. 320 cols * 100 ms =
// ~32 s of visible history, advancing at a constant speed in time.
const WF_TICK_MS = 100;
// A capture marker is held for this many columns so it renders as a clearly
// visible red band rather than a single easy-to-miss pixel line.
const CAPTURE_MARK_COLS = 4;

/**
 * Map an RSSI dBm value to an RGB color across a dark-blue -> cyan -> green
 * -> yellow -> red gradient. Values outside [RSSI_MIN, RSSI_MAX] are clamped.
 */
function rssiToRgb(rssi) {
  let t = (rssi - RSSI_MIN) / (RSSI_MAX - RSSI_MIN);
  if (t < 0) t = 0;
  if (t > 1) t = 1;

  const stops = [
    [10, 22, 40],
    [0, 80, 160],
    [0, 200, 200],
    [120, 220, 60],
    [255, 220, 40],
    [255, 80, 40],
  ];
  const seg = t * (stops.length - 1);
  const i = Math.min(stops.length - 2, Math.floor(seg));
  const f = seg - i;
  const a = stops[i];
  const b = stops[i + 1];
  return [
    Math.round(a[0] + (b[0] - a[0]) * f),
    Math.round(a[1] + (b[1] - a[1]) * f),
    Math.round(a[2] + (b[2] - a[2]) * f),
  ];
}

function formatSignal(sig) {
  if (sig.is_raw) {
    return {
      idx: sig.idx,
      type: 'RAW',
      freq: Number(sig.freq).toFixed(2),
      serial: '-',
      btn: '-',
      cnt: '-',
      mf: `${sig.edges}e`,
    };
  }
  // WS RX events carry the protocol family as `signalType` (since `type`
  // is reserved for the WS event tag). HTTP /api/subghz/list responses
  // use `type` directly. Support both.
  const proto = sig.signalType || sig.type || '-';
  // Generic protocols (HOLTEK etc.) emit `id`, KeeLoq/StarLine emit `serial`.
  const idOrSerial = sig.serial || sig.id || '-';
  return {
    idx: sig.idx,
    type: proto,
    freq: Number(sig.freq).toFixed(2),
    serial: idOrSerial,
    btn: sig.btn != null && sig.btn !== 0 ? String(sig.btn) : (sig.btn === 0 ? '0' : '-'),
    cnt: sig.cnt != null && sig.cnt !== 0 ? String(sig.cnt) : (sig.cnt === 0 ? '0' : '-'),
    mf: sig.mf || (sig.bits ? `${sig.bits}b` : '-'),
  };
}

export function SubGhzListen() {
  const [freq, setFreq] = useState('433.92');
  const [raw, setRaw] = useState(false);
  const [running, setRunning] = useState(false);
  const [signals, setSignals] = useState([]);
  const [lastRssi, setLastRssi] = useState(null);
  // Per-idx save state: 'saving' | 'saved' | 'error'
  const [saveState, setSaveState] = useState({});

  const canvasRef = useRef(null);
  const ctxRef = useRef(null);
  const seenIdxRef = useRef(new Set());
  const rawRef = useRef(false);
  // Highest RSSI seq consumed, so the WS and HTTP-fallback paths don't
  // redundantly re-apply the same sample.
  const rssiSeqRef = useRef(-1);
  // Latest known RSSI value. The waterfall is drawn from this at a fixed
  // rate (see the render-timer effect) so it advances linearly in time,
  // rather than only when a ~1 Hz sample happens to arrive.
  const currentRssiRef = useRef(null);
  // Columns still owed to a capture marker (drawn red). Set when a signal is
  // captured so the waterfall always shows a mark, decremented per render tick.
  const captureHoldRef = useRef(0);
  // The HTTP list poll picks up captures already sitting in device mem when a
  // session starts; those are seeded once (baseline) without a marker so only
  // genuinely new arrivals flag the waterfall.
  const rxBaselineRef = useRef(false);

  useEffect(() => {
    rawRef.current = raw;
  }, [raw]);

  useEffect(() => {
    const cvs = canvasRef.current;
    if (!cvs) return;
    cvs.width = WF_WIDTH;
    cvs.height = WF_HEIGHT;
    const ctx = cvs.getContext('2d');
    ctx.fillStyle = '#0A1628';
    ctx.fillRect(0, 0, WF_WIDTH, WF_HEIGHT);
    ctxRef.current = ctx;
  }, []);

  // Recover from a Mate-host reboot: re-list the volatile mem cache and seed
  // the table from whatever captures already exist on the device.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetchSubghzListAfterRefresh('mem', 3000);
        if (cancelled || !res?.ok || !res.signals?.length) return;
        const seen = seenIdxRef.current;
        for (const s of res.signals) seen.add(s.idx);
        setSignals((prev) => mergeSubghzSignals(prev, res.signals));
      } catch (_) {
        // best-effort
      }
    })();
    return () => { cancelled = true; };
  }, []);

  // Fallback while LIVE: the Mate host caches each [SUBGHZ_RX] on the HTTP
  // side immediately (cache_subghz_signal). Poll that cache in case a WS
  // frame was dropped — same class of race that left Transmit empty on load.
  useEffect(() => {
    if (!running) return undefined;
    let cancelled = false;
    const poll = async () => {
      try {
        const res = await api.subghzList();
        if (cancelled || !res?.ok || !res.signals?.length) return;
        const seen = seenIdxRef.current;
        let newCount = 0;
        for (const s of res.signals) {
          if (!seen.has(s.idx)) {
            seen.add(s.idx);
            newCount++;
          }
        }
        if (rxBaselineRef.current && newCount > 0) {
          captureHoldRef.current = CAPTURE_MARK_COLS;
        }
        rxBaselineRef.current = true;
        setSignals((prev) => mergeSubghzSignals(prev, res.signals));
      } catch (_) {
        /* ignore transient fetch errors while listening */
      }
    };
    poll();
    const id = setInterval(poll, 1200);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [running]);

  // Waterfall RSSI fallback: the WS `subghz_rssi` stream is primary, but if
  // it is unavailable the waterfall would stall. Poll the latest sample and
  // feed it into the shared `currentRssiRef` when its `seq` advances (the
  // render timer below does the actual drawing).
  useEffect(() => {
    if (!running) return undefined;
    let cancelled = false;
    const poll = async () => {
      try {
        const res = await api.subghzRssi();
        if (cancelled || !res?.ok) return;
        if (res.seq > rssiSeqRef.current) {
          rssiSeqRef.current = res.seq;
          currentRssiRef.current = res.rssi;
          setLastRssi(res.rssi);
        }
      } catch (_) {
        /* ignore transient fetch errors while listening */
      }
    };
    poll();
    const id = setInterval(poll, 700);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [running]);

  // Fixed-rate waterfall renderer: push one column every WF_TICK_MS using the
  // latest known RSSI, so the display scrolls at a constant speed in time
  // (independent of the ~1 Hz sample rate). Before the first sample arrives we
  // draw the noise floor so motion is visible immediately.
  useEffect(() => {
    if (!running) return undefined;
    const id = setInterval(() => {
      const rssi = currentRssiRef.current != null ? currentRssiRef.current : RSSI_MIN;
      let capture = false;
      if (captureHoldRef.current > 0) {
        capture = true;
        captureHoldRef.current -= 1;
      }
      pushRssiColumn(rssi, capture);
    }, WF_TICK_MS);
    return () => clearInterval(id);
  }, [running]);

  function pushRssiColumn(rssi, capture) {
    const ctx = ctxRef.current;
    if (!ctx) return;
    const img = ctx.getImageData(1, 0, WF_WIDTH - 1, WF_HEIGHT);
    ctx.putImageData(img, 0, 0);

    if (capture) {
      // Unmistakable capture marker: full-height bright red bar with a white
      // cap, so a decoded/raw signal is always visible on the waterfall.
      ctx.fillStyle = '#ff2323';
      ctx.fillRect(WF_WIDTH - 1, 0, 1, WF_HEIGHT);
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(WF_WIDTH - 1, 0, 1, 3);
      return;
    }

    const [r, g, b] = rssiToRgb(rssi);
    ctx.fillStyle = `rgb(${r},${g},${b})`;
    ctx.fillRect(WF_WIDTH - 1, 0, 1, WF_HEIGHT);
  }

  useEffect(() => wsAddListener((msg) => {
    if (msg.type === 'subghz_rssi') {
      // Dedup against the HTTP fallback: apply each sample once. Drawing is
      // handled by the fixed-rate render timer, not here.
      if (msg.seq != null && msg.seq <= rssiSeqRef.current) return;
      if (msg.seq != null) rssiSeqRef.current = msg.seq;
      currentRssiRef.current = msg.rssi;
      setLastRssi(msg.rssi);
    } else if (msg.type === 'subghz_rx' || msg.type === 'subghz_raw') {
      const sig = { ...msg, is_raw: msg.type === 'subghz_raw' };
      if (rawRef.current && msg.type === 'subghz_rx') return;
      if (!rawRef.current && msg.type === 'subghz_raw') return;
      if (!sig.idx) return;
      const seen = seenIdxRef.current;
      if (seen.has(sig.idx)) return;
      seen.add(sig.idx);
      captureHoldRef.current = CAPTURE_MARK_COLS;
      setSignals((prev) => mergeSubghzSignals(prev, [sig]));
    } else if (msg.type === 'subghz_save_done') {
      setSaveState((prev) => ({ ...prev, [msg.idx]: 'saved' }));
      showToast(`Saved to SD${msg.name ? `: ${msg.name}` : ` #${msg.idx}`}`, 'success');
    } else if (msg.type === 'subghz_save_err') {
      setSaveState((prev) => ({ ...prev, [msg.idx]: 'error' }));
      showToast(`Save failed #${msg.idx}${msg.reason ? ` (${msg.reason})` : ''}`, 'error');
    } else if (msg.type === 'attack_stopped') {
      setRunning(false);
    }
  }), []);

  async function saveToSd(idx) {
    if (!idx) return;
    setSaveState((prev) => ({ ...prev, [idx]: 'saving' }));
    const res = await api.subghzSave(idx);
    if (!res.ok) {
      setSaveState((prev) => ({ ...prev, [idx]: 'error' }));
      showToast(res.error || 'Save failed', 'error');
    }
    // success/failure confirmation arrives via the subghz_save_* WS event
  }

  async function start() {
    const f = parseFloat(freq);
    if (!isFinite(f) || f <= 0) {
      showToast('Invalid frequency', 'warning');
      return;
    }
    seenIdxRef.current = new Set();
    currentRssiRef.current = null;
    captureHoldRef.current = 0;
    rxBaselineRef.current = false;
    setSignals([]);
    setSaveState({});
    const res = await api.subghzListen(f, raw);
    if (res.ok) {
      setRunning(true);
      showToast(`Listening on ${f.toFixed(2)} MHz${raw ? ' (raw)' : ''}`, 'success');
    } else {
      showToast(res.error || 'Listen failed', 'error');
    }
  }

  async function stop() {
    await api.subghzStop();
    setRunning(false);
  }

  return (
    <Layout title="SubGHZ Listen" back="/subghz" onBack={() => api.subghzStop()}>
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Receiver</h3>
          <span class="badge">{running ? 'LIVE' : 'idle'}</span>
        </div>

        <div class="field">
          <label class="field-label">Frequency (MHz)</label>
          <input
            class="input"
            type="number"
            step="0.01"
            min="300"
            max="928"
            value={freq}
            disabled={running}
            onInput={(e) => setFreq(e.currentTarget.value)}
          />
        </div>

        <div class="btn-row">
          <button
            class={raw ? 'btn btn-info' : 'btn btn-soft'}
            onClick={() => setRaw((v) => !v)}
            disabled={running}
          >
            {raw ? 'RAW' : 'Decoded'}
          </button>
          {!running ? (
            <button class="btn btn-primary" onClick={start}>Start</button>
          ) : (
            <button class="btn btn-danger" onClick={stop}>Stop</button>
          )}
        </div>

        <div class="kv">
          <div class="kv-row">
            <span class="kv-key">Last RSSI</span>
            <span class="kv-val">{lastRssi != null ? `${lastRssi} dBm` : '-'}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">Captured</span>
            <span class="kv-val">{signals.length}</span>
          </div>
        </div>

        <div style="margin-top:12px">
          <canvas
            ref={canvasRef}
            style={`width:100%;height:120px;display:block;background:#0A1628;border-radius:6px;image-rendering:pixelated`}
          />
          <div style="display:flex;justify-content:space-between;font-size:11px;color:#9aaecf;margin-top:4px">
            <span>{RSSI_MIN} dBm</span>
            <span>waterfall (left = older)</span>
            <span>{RSSI_MAX} dBm</span>
          </div>
        </div>
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Captured Signals</h3>
        </div>
        {signals.length ? (
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Type</th>
                  <th>MHz</th>
                  <th>Serial</th>
                  <th>Btn</th>
                  <th>Cnt</th>
                  <th>Mf</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {signals.map((s) => {
                  const f = formatSignal(s);
                  const state = saveState[f.idx];
                  return (
                    <tr key={f.idx}>
                      <td>{f.idx}</td>
                      <td>{f.type}</td>
                      <td>{f.freq}</td>
                      <td>{f.serial}</td>
                      <td>{f.btn}</td>
                      <td>{f.cnt}</td>
                      <td>{f.mf}</td>
                      <td style="text-align:right">
                        {state === 'saved' ? (
                          <span class="chip chip-success">Saved</span>
                        ) : (
                          <button
                            class={`chip ${state === 'error' ? 'chip-danger' : 'chip-action'}`}
                            disabled={state === 'saving'}
                            onClick={() => saveToSd(f.idx)}
                            title="Save to SD library"
                          >
                            {state === 'saving'
                              ? 'Saving...'
                              : state === 'error'
                              ? 'Retry'
                              : 'Save to SD'}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div class="empty-state">No signals captured yet.</div>
        )}
      </section>
    </Layout>
  );
}
