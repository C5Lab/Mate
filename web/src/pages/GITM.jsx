import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { api } from '../api';
import { getState } from '../store';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';
import { CgwLive } from '../components/CgwLive';

const POLL_MS = 3000;

function isOpenSecurity(security) {
  return !security || /open/i.test(security);
}

/* gitm_YYYYMMDD_HHMMSS -> matches Tab5's auto basename convention. */
function defaultPcapPrefix() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `gitm_${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}_` +
    `${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

/**
 * GITM (Capture Gateway) wizard: connect an upstream network, stand up a
 * dedicated NAPT + PCAP SoftAP, then watch the live gateway. Mirrors the Tab5
 * three-step flow, adapted to Mate's REST/WS transport.
 */
export function GITM() {
  const st = getState();
  const [step, setStep] = useState('upstream'); // upstream | ap | live
  const [busy, setBusy] = useState(false);

  // Step 1 — upstream
  const [upSsid, setUpSsid] = useState('');
  const [upSecurity, setUpSecurity] = useState('');
  const [upPassword, setUpPassword] = useState('');

  // Step 2 — AP
  const [apSsid, setApSsid] = useState('JanOS-Capture');
  const [apSecure, setApSecure] = useState(true);
  const [apPassword, setApPassword] = useState('');
  const [pcapPrefix, setPcapPrefix] = useState('');

  // Step 3 — live
  const [snap, setSnap] = useState(null);
  const [final, setFinal] = useState(null);

  const pollRef = useRef(null);
  const mounted = useRef(true);

  function stopPolling() {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }

  async function pollOnce() {
    try {
      await api.gitmRefresh();
      await new Promise((r) => setTimeout(r, 400));
      const res = await api.gitmStatus();
      if (!mounted.current || !res || !res.ok) return;
      setSnap(res);
      if (res.final && res.final.valid) setFinal(res.final);
    } catch (_) { /* ignore, next tick retries */ }
  }

  function startPolling() {
    stopPolling();
    pollOnce();
    pollRef.current = setInterval(pollOnce, POLL_MS);
  }

  useEffect(() => {
    mounted.current = true;
    setPcapPrefix(defaultPcapPrefix());

    // Preselect a single selected scan target as the upstream candidate.
    const sel = st.networks.find((n) => st.selected.has(n.index));
    if (sel?.ssid) { setUpSsid(sel.ssid); setUpSecurity(sel.security || ''); }

    // Adopt an already-running gateway (e.g. after a reload).
    (async () => {
      try {
        const res = await api.gitmStatus();
        if (mounted.current && res?.ok && res.active) {
          setSnap(res);
          if (res.final?.valid) setFinal(res.final);
          setStep('live');
          startPolling();
        }
      } catch (_) { /* ignore */ }
    })();

    const removeWs = wsAddListener((msg) => {
      if (msg.type === 'cgw_final') setFinal({ valid: true, ...msg });
      if (msg.type === 'attack_stopped') stopPolling();
    });

    return () => { mounted.current = false; stopPolling(); removeWs(); };
  }, []);

  function pickUpstream(e) {
    const idx = Number(e.target.value);
    const net = st.networks.find((n) => n.index === idx);
    if (net) { setUpSsid(net.ssid); setUpSecurity(net.security || ''); setUpPassword(''); }
  }

  async function connectUpstream() {
    if (!upSsid.trim()) { showToast('Pick or enter an upstream network', 'warning'); return; }
    if (!isOpenSecurity(upSecurity) && !upPassword) {
      showToast('Enter the upstream WiFi password', 'warning');
      return;
    }
    setBusy(true);
    try {
      const res = await api.wifiConnect(upSsid.trim(), upPassword);
      if (!res.ok) { showToast(res.error || 'Connect rejected', 'error'); return; }
      // Wait for the connection result: WS event first, status poll as fallback.
      const ok = await waitForConnect();
      if (ok) {
        showToast(`Connected to ${upSsid.trim()}`, 'success');
        setStep('ap');
      } else {
        showToast('Upstream connect failed', 'error');
      }
    } finally {
      setBusy(false);
    }
  }

  function waitForConnect(timeoutMs = 20000) {
    return new Promise((resolve) => {
      let done = false;
      const finish = (val) => { if (!done) { done = true; cleanup(); resolve(val); } };
      const remove = wsAddListener((msg) => {
        if (msg.type === 'wifi_connected') finish(true);
        if (msg.type === 'wifi_connect_failed') finish(false);
      });
      const poll = setInterval(async () => {
        try {
          const s = await api.status();
          if (s?.ok && s.sta_connected) finish(true);
        } catch (_) { /* ignore */ }
      }, 1500);
      const timer = setTimeout(() => finish(false), timeoutMs);
      function cleanup() { remove(); clearInterval(poll); clearTimeout(timer); }
    });
  }

  async function startGitm() {
    if (!apSsid.trim()) { showToast('AP SSID is required', 'warning'); return; }
    if (apSecure && (apPassword.length < 8 || apPassword.length > 63)) {
      showToast('WPA2 password must be 8-63 chars', 'warning');
      return;
    }
    setBusy(true);
    try {
      const res = await api.gitmStart(
        apSsid.trim(),
        apSecure ? apPassword : '',
        pcapPrefix.trim(),
      );
      if (res.ok) {
        setStep('live');
        setFinal(null);
        startPolling();
        showToast('Capture Gateway starting...', 'success');
      } else {
        showToast(res.error || 'Failed to start GITM', 'error');
      }
    } finally {
      setBusy(false);
    }
  }

  async function stop() {
    setBusy(true);
    try {
      await api.stop();
      // One last poll picks up the [PCAP_FINAL] summary + active=0.
      setTimeout(pollOnce, 800);
      showToast('Stopping and finalizing PCAP...', 'warning');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Layout
      title="GITM (Capture Gateway)"
      subtitle="Authorized NAPT gateway + PCAP. Connect an uplink, then bring up your capture AP."
      back="/"
    >
      {step === 'upstream' ? (
        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">1. Internet uplink</h3>
          </div>
          {st.networks.length ? (
            <div class="field">
              <label class="field-label">Pick a scanned network</label>
              <select class="select" onChange={pickUpstream} value={
                (st.networks.find((n) => n.ssid === upSsid) || {}).index || ''
              }>
                <option value="">-- choose --</option>
                {st.networks.map((n) => (
                  <option key={n.index} value={n.index}>
                    {n.ssid || '(hidden)'} · {n.security || 'open'} · {n.rssi}dBm
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <div class="alert warn">No scan results. Run a WiFi scan first, or type the SSID below.</div>
          )}
          <div class="field">
            <label class="field-label">Upstream SSID</label>
            <input class="input" type="text" maxLength={32} value={upSsid}
              onInput={(e) => setUpSsid(e.target.value)} placeholder="Office WiFi" />
          </div>
          {!isOpenSecurity(upSecurity) ? (
            <div class="field">
              <label class="field-label">Upstream password</label>
              <input class="input" type="text" value={upPassword}
                onInput={(e) => setUpPassword(e.target.value)} placeholder="WiFi password" />
            </div>
          ) : null}
          <div class="btn-row">
            <button class="btn btn-primary" onClick={connectUpstream} disabled={busy}>
              {busy ? 'Connecting...' : 'Connect uplink'}
            </button>
          </div>
        </section>
      ) : null}

      {step === 'ap' ? (
        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">2. Your capture AP</h3>
            <span class="badge ok">uplink: {upSsid}</span>
          </div>
          <div class="field">
            <label class="field-label">AP SSID</label>
            <input class="input" type="text" maxLength={32} value={apSsid}
              onInput={(e) => setApSsid(e.target.value)} placeholder="JanOS-Capture" />
          </div>
          <div class="field">
            <label class="field-label">Security</label>
            <select class="select" value={apSecure ? 'wpa2' : 'open'}
              onChange={(e) => setApSecure(e.target.value === 'wpa2')}>
              <option value="wpa2">WPA2</option>
              <option value="open">Open</option>
            </select>
          </div>
          {apSecure ? (
            <div class="field">
              <label class="field-label">AP password (8-63 chars)</label>
              <input class="input" type="text" value={apPassword}
                onInput={(e) => setApPassword(e.target.value)} placeholder="Minimum 8 chars" />
            </div>
          ) : null}
          <div class="field">
            <label class="field-label">PCAP name prefix</label>
            <input class="input" type="text" maxLength={90} value={pcapPrefix}
              onInput={(e) => setPcapPrefix(e.target.value)} placeholder="gitm_..." />
          </div>
          <div class="btn-row">
            <button class="btn" onClick={() => setStep('upstream')} disabled={busy}>Back</button>
            <button class="btn btn-primary" onClick={startGitm} disabled={busy}>
              {busy ? 'Starting...' : 'Start GITM'}
            </button>
          </div>
        </section>
      ) : null}

      {step === 'live' ? (
        <>
          <section class="glass-card card-body reveal">
            <div class="btn-row">
              <button class="btn btn-danger" onClick={stop} disabled={busy}>Stop GITM</button>
            </div>
          </section>
          <CgwLive snap={snap} final={final} />
        </>
      ) : null}
    </Layout>
  );
}
