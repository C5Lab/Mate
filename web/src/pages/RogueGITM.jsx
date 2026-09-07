import { useEffect, useRef, useState } from 'preact/hooks';
import { route } from 'preact-router';
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

/**
 * Rogue GITM: mirror a victim AP (WPA2 SoftAP clone) while gatewaying its
 * clients through an uplink, recording to PCAP. Requires exactly one selected
 * victim on the Scan page. Connects the uplink, selects the victim for the
 * optional same-channel deauth, then fires start_rogue_gitm. After start it
 * reuses the shared Capture Gateway live view + universal stop.
 */
export function RogueGITM() {
  const st = getState();
  const victim = st.networks.find((n) => st.selected.has(n.index)) || null;

  // Uplink candidates: named networks on the victim's channel, excluding the
  // victim's own BSSID (matches Tab5's uplink dropdown constraint).
  const uplinks = victim
    ? st.networks.filter((n) =>
        n.index !== victim.index &&
        n.bssid !== victim.bssid &&
        n.channel === victim.channel &&
        n.ssid)
    : [];

  const [uplinkIdx, setUplinkIdx] = useState(uplinks[0]?.index ?? '');
  const [uplinkPassword, setUplinkPassword] = useState('');
  const [mirrorPassword, setMirrorPassword] = useState('');
  const [running, setRunning] = useState(false);
  const [busy, setBusy] = useState(false);

  const [snap, setSnap] = useState(null);
  const [final, setFinal] = useState(null);

  const pollRef = useRef(null);
  const mounted = useRef(true);

  const uplink = st.networks.find((n) => n.index === Number(uplinkIdx)) || null;

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
    } catch (_) { /* ignore */ }
  }

  function startPolling() {
    stopPolling();
    pollOnce();
    pollRef.current = setInterval(pollOnce, POLL_MS);
  }

  useEffect(() => {
    mounted.current = true;

    (async () => {
      try {
        const res = await api.gitmStatus();
        if (mounted.current && res?.ok && res.active) {
          setSnap(res);
          if (res.final?.valid) setFinal(res.final);
          setRunning(true);
          startPolling();
        }
      } catch (_) { /* ignore */ }
    })();

    const removeWs = wsAddListener((msg) => {
      if (msg.type === 'attack_started' && msg.attack === 'rogue_gitm') setRunning(true);
      if (msg.type === 'cgw_final') setFinal({ valid: true, ...msg });
      if (msg.type === 'attack_stopped') { setRunning(false); stopPolling(); }
    });

    return () => { mounted.current = false; stopPolling(); removeWs(); };
  }, []);

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

  async function start() {
    if (!victim) { showToast('Select one victim on the Scan page', 'warning'); return; }
    if (!uplink) { showToast('Pick an uplink network', 'warning'); return; }
    if (!isOpenSecurity(uplink.security) && !uplinkPassword) {
      showToast('Enter the uplink password', 'warning');
      return;
    }
    if (mirrorPassword.length < 8 || mirrorPassword.length > 63) {
      showToast('Mirror password must be 8-63 chars', 'warning');
      return;
    }
    setBusy(true);
    try {
      const conn = await api.wifiConnect(uplink.ssid, uplinkPassword);
      if (!conn.ok) { showToast(conn.error || 'Uplink connect rejected', 'error'); return; }
      const connected = await waitForConnect();
      if (!connected) { showToast('Uplink connect failed', 'error'); return; }

      // Select the victim so JanOS can run the optional same-channel deauth.
      await api.select([victim.index]);

      const res = await api.rogueGitm(victim.ssid, mirrorPassword);
      if (res.ok) {
        setRunning(true);
        setFinal(null);
        startPolling();
        showToast('Rogue GITM starting...', 'success');
      } else {
        showToast(res.error || 'Failed to start Rogue GITM', 'error');
      }
    } finally {
      setBusy(false);
    }
  }

  async function stop() {
    setBusy(true);
    try {
      await api.stop();
      setRunning(false);
      setTimeout(pollOnce, 800);
      showToast('Stopping and finalizing PCAP...', 'warning');
    } finally {
      setBusy(false);
    }
  }

  if (!victim) {
    return (
      <Layout title="Rogue GITM" back="/scan">
        <section class="glass-card card-body reveal">
          <div class="alert warn">
            Select exactly one victim network on the Scan page, then open Rogue GITM.
          </div>
          <div class="btn-row">
            <button class="btn btn-primary" onClick={() => route('/scan')}>Go to Scan</button>
          </div>
        </section>
      </Layout>
    );
  }

  return (
    <Layout
      title="Rogue GITM"
      subtitle="WPA2 mirror of a victim AP + Capture Gateway. Same-channel uplink required."
      back="/scan"
    >
      {!running ? (
        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">Victim</h3>
            <span class="badge info">CH {victim.channel}</span>
          </div>
          <div class="kv">
            <div class="kv-row"><span class="kv-key">SSID</span><span class="kv-val">{victim.ssid || '(hidden)'}</span></div>
            <div class="kv-row"><span class="kv-key">BSSID</span><span class="kv-val">{victim.bssid}</span></div>
            <div class="kv-row"><span class="kv-key">Security</span><span class="kv-val">{victim.security || 'open'}</span></div>
          </div>

          <div class="section-head" style="margin-top:12px;">
            <h3 class="section-title">Uplink (same channel)</h3>
          </div>
          {uplinks.length ? (
            <div class="field">
              <label class="field-label">Uplink network</label>
              <select class="select" value={String(uplinkIdx)}
                onChange={(e) => { setUplinkIdx(e.target.value); setUplinkPassword(''); }}>
                {uplinks.map((n) => (
                  <option key={n.index} value={n.index}>
                    {n.ssid} · {n.security || 'open'} · {n.rssi}dBm
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <div class="alert warn">
              No other named networks on channel {victim.channel}. Rogue GITM needs a
              same-channel uplink. Run a fresh scan or pick a different victim.
            </div>
          )}
          {uplink && !isOpenSecurity(uplink.security) ? (
            <div class="field">
              <label class="field-label">Uplink password</label>
              <input class="input" type="text" value={uplinkPassword}
                onInput={(e) => setUplinkPassword(e.target.value)} placeholder="Uplink WiFi password" />
            </div>
          ) : null}

          <div class="field">
            <label class="field-label">Mirror password (victim WPA2, 8-63 chars)</label>
            <input class="input" type="text" value={mirrorPassword}
              onInput={(e) => setMirrorPassword(e.target.value)} placeholder="Victim's real WPA2 key" />
          </div>

          <div class="btn-row">
            <button class="btn btn-danger" onClick={start} disabled={busy || !uplinks.length}>
              {busy ? 'Starting...' : 'Start Rogue GITM'}
            </button>
          </div>
        </section>
      ) : (
        <>
          <section class="glass-card card-body reveal">
            <div class="btn-row">
              <button class="btn btn-danger" onClick={stop} disabled={busy}>Stop Rogue GITM</button>
            </div>
          </section>
          <CgwLive snap={snap} final={final} />
        </>
      )}
    </Layout>
  );
}
