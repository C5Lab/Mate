import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../../components/Layout';
import { api } from '../../api';
import { showToast } from '../../components/Toast';
import { wsAddListener } from '../../ws';

const WF_WIDTH = 320;
const WF_HEIGHT = 60;
const RSSI_MIN = -110;
const RSSI_MAX = -40;

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

  const canvasRef = useRef(null);
  const ctxRef = useRef(null);
  const seenIdxRef = useRef(new Set());
  const rawRef = useRef(false);

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

  // Recover from a Mate-host reboot: ask the host to re-list the JanOS
  // keystore and seed the table from whatever signals already exist on
  // the device, so previously-captured signals don't look "lost".
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        await api.subghzListRefresh();
        const res = await api.subghzList();
        if (cancelled || !res?.ok || !res.signals?.length) return;
        const seen = seenIdxRef.current;
        const seeded = [];
        for (const s of res.signals) {
          if (seen.has(s.idx)) continue;
          seen.add(s.idx);
          seeded.push({ ...s, signalType: s.type });
        }
        if (seeded.length) {
          setSignals((prev) => [...seeded.reverse(), ...prev].slice(0, 200));
        }
      } catch (_) {
        // best-effort; nothing to show if it fails
      }
    })();
    return () => { cancelled = true; };
  }, []);

  function pushRssiColumn(rssi) {
    const ctx = ctxRef.current;
    if (!ctx) return;
    const img = ctx.getImageData(1, 0, WF_WIDTH - 1, WF_HEIGHT);
    ctx.putImageData(img, 0, 0);

    const [r, g, b] = rssiToRgb(rssi);
    ctx.fillStyle = `rgb(${r},${g},${b})`;
    ctx.fillRect(WF_WIDTH - 1, 0, 1, WF_HEIGHT);

    if ((WF_WIDTH - 1) % 32 === 0) {
      ctx.fillStyle = '#152540';
    }
  }

  useEffect(() => wsAddListener((msg) => {
    if (msg.type === 'subghz_rssi') {
      setLastRssi(msg.rssi);
      pushRssiColumn(msg.rssi);
    } else if (msg.type === 'subghz_rx' || msg.type === 'subghz_raw') {
      const sig = { ...msg, is_raw: msg.type === 'subghz_raw' };
      if (rawRef.current && msg.type === 'subghz_rx') return;
      if (!rawRef.current && msg.type === 'subghz_raw') return;
      const seen = seenIdxRef.current;
      if (seen.has(sig.idx)) return;
      seen.add(sig.idx);
      setSignals((prev) => [sig, ...prev].slice(0, 200));
    } else if (msg.type === 'attack_stopped') {
      setRunning(false);
    }
  }), []);

  async function start() {
    const f = parseFloat(freq);
    if (!isFinite(f) || f <= 0) {
      showToast('Invalid frequency', 'warning');
      return;
    }
    seenIdxRef.current = new Set();
    setSignals([]);
    const res = await api.subghzListen(f, raw);
    if (res.ok) {
      setRunning(true);
      showToast(`Listening on ${f.toFixed(2)} MHz${raw ? ' (raw)' : ''}`, 'success');
    } else {
      showToast(res.error || 'Listen failed', 'error');
    }
  }

  async function stop() {
    await api.stop();
    setRunning(false);
  }

  return (
    <Layout title="SubGHZ Listen" back="/subghz">
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
                </tr>
              </thead>
              <tbody>
                {signals.map((s) => {
                  const f = formatSignal(s);
                  return (
                    <tr key={f.idx}>
                      <td>{f.idx}</td>
                      <td>{f.type}</td>
                      <td>{f.freq}</td>
                      <td>{f.serial}</td>
                      <td>{f.btn}</td>
                      <td>{f.cnt}</td>
                      <td>{f.mf}</td>
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
