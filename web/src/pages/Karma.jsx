import { useEffect, useRef, useState } from 'preact/hooks';
import { route } from 'preact-router';
import { Layout } from '../components/Layout';
import { PortalPicker } from '../components/PortalPicker';
import { api } from '../api';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';

function parseFormFields(data) {
  return String(data || '')
    .split('&')
    .map((pair) => {
      const idx = pair.indexOf('=');
      if (idx < 0) return { key: pair, value: '' };
      return {
        key: decodeURIComponent(pair.slice(0, idx).replace(/\+/g, ' ')),
        value: decodeURIComponent(pair.slice(idx + 1).replace(/\+/g, ' ')),
      };
    })
    .filter((f) => f.key);
}

function readQuery() {
  if (typeof window === 'undefined') return { probe: 0, ssid: '' };
  const params = new URLSearchParams(window.location.search || '');
  const probe = parseInt(params.get('probe') || '0', 10);
  const ssid = params.get('ssid') || '';
  return { probe: Number.isFinite(probe) ? probe : 0, ssid };
}

export function Karma() {
  const [{ probe, ssid }, setQuery] = useState(readQuery());
  const [running, setRunning] = useState(false);
  const [portalSelected, setPortalSelected] = useState(false);
  const [passwords, setPasswords] = useState([]);
  const [verified, setVerified] = useState(false);
  const [clients, setClients] = useState([]);
  const [stopping, setStopping] = useState(true);
  const [probes, setProbes] = useState([]);
  const stoppedRef = useRef(false);

  useEffect(() => {
    setQuery(readQuery());

    /* Stop any running attack so the state machine is idle for portal listing
     * and the upcoming start_karma command. We always do this on mount of the
     * Karma page -- the user typically arrives here from the Network Observer
     * which keeps the sniffer running. */
    (async () => {
      if (stoppedRef.current) return;
      stoppedRef.current = true;
      try {
        await api.stop();
      } catch (e) {
        /* ignore -- worst case PortalPicker will retry */
      }
      setStopping(false);

      /* If we arrived without a probe in the URL (e.g. from the Attacks menu),
       * offer the probe list cached on the device from the last observer run. */
      const q = readQuery();
      if (!q.probe) {
        try {
          const data = await api.probes();
          if (data?.ok && Array.isArray(data.probes)) {
            setProbes(data.probes);
          }
        } catch (e) {
          /* ignore -- fallback button routes to the observer */
        }
      }
    })();

    const removeWs = wsAddListener((msg) => {
      if (msg.type === 'attack_started' && msg.attack === 'karma') {
        setRunning(true);
      }

      if (msg.type === 'attack_stopped') {
        setRunning(false);
      }

      if (msg.type === 'client_connected') {
        setClients((prev) => prev.includes(msg.mac) ? prev : [...prev, msg.mac]);
      }

      if (msg.type === 'client_disconnected') {
        setClients((prev) => prev.filter((m) => m !== msg.mac));
      }

      // The credential list is rebuilt from the device-cached REST endpoint
      // (source of truth); these WS events are only for the instant toast.
      if (msg.type === 'portal_data') {
        const fields = parseFormFields(msg.data);
        const summary = fields.map((f) => `${f.key}=${f.value}`).join('  ');
        showToast(`Credentials captured: ${summary}`, 'success');
      }

      if (msg.type === 'password_received') {
        showToast(`Password captured: ${msg.password}`, 'success');
      }

      if (msg.type === 'password_verified') {
        setVerified(true);
        showToast('Password verified by target!', 'success');
      }
    });

    // Poll device-cached captures every 2s so credentials survive WS drops.
    let alive = true;
    async function pollCaptures() {
      try {
        const res = await api.portalCaptures();
        if (!alive || !res || !res.ok) return;
        const list = (res.captures || []).map((c, i) => {
          const fields = parseFormFields(c.data);
          const summary = fields.map((f) => `${f.key}=${f.value}`).join('  ') || c.data;
          return { id: `${c.at}-${i}`, password: summary, fields };
        }).reverse();
        setPasswords(list);
      } catch (_) { /* ignore */ }
    }
    pollCaptures();
    const capTimer = setInterval(pollCaptures, 2000);

    return () => { alive = false; clearInterval(capTimer); removeWs(); };
  }, []);

  async function start() {
    if (!probe || probe <= 0) {
      showToast('Pick a probe from the Network Observer first', 'warning');
      return;
    }
    if (!portalSelected) {
      showToast('Select an SD portal template', 'warning');
      return;
    }

    const res = await api.karma(probe);
    if (res.ok) {
      setRunning(true);
      setPasswords([]);
      setClients([]);
      setVerified(false);
      showToast(`Karma started against probe #${probe}`, 'success');
    } else {
      showToast(res.error || 'Failed to start Karma', 'error');
    }
  }

  async function stop() {
    await api.stop();
    setRunning(false);
    showToast('Karma stopped', 'warning');
  }

  const lastPassword = passwords[0];

  return (
    <Layout
      title="Karma Attack"
      subtitle="Spoof an SSID a target device is probing for, then serve a captive portal."
      back="/sniffer"
    >
      <section class="glass-card card-body reveal">
        <div class="kv">
          <div class="kv-row">
            <span class="kv-key">Probe target</span>
            <span class="kv-val">{ssid || (probe ? '[hidden SSID]' : 'No probe selected')}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">Probe index</span>
            <span class="kv-val">{probe || '—'}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">Connected clients</span>
            <span class="kv-val">{clients.length}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">Status</span>
            <span class="kv-val">
              {stopping ? 'Stopping previous activity...' : running ? 'Karma running' : 'Idle'}
            </span>
          </div>
        </div>

        {!probe ? (
          probes.length > 0 ? (
            <div style="margin-top:12px">
              <div class="section-head">
                <h3 class="section-title">Pick a probe</h3>
                <span class="badge">{probes.length}</span>
              </div>
              <ul class="probe-list">
                {probes.map((p) => (
                  <li key={`${p.index}-${p.ssid}`}>
                    <button
                      class="probe-item"
                      onClick={() => setQuery({ probe: p.index, ssid: p.ssid || '' })}
                    >
                      <span class="probe-idx">{p.index}</span>
                      <span class="probe-ssid">{p.ssid || '[hidden]'}</span>
                      <span class="probe-cta">Select →</span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div class="alert warn" style="margin-top:12px">
              No probe selected. Open the Network Observer, run a scan, and click a probe.
              <div class="btn-row" style="margin-top:8px">
                <button class="btn btn-secondary" onClick={() => route('/sniffer')}>
                  Go to Network Observer
                </button>
              </div>
            </div>
          )
        ) : null}

        {!running && !stopping ? <PortalPicker onSelect={(idx) => setPortalSelected(idx > 0)} /> : null}

        <div class="btn-row">
          {!running ? (
            <button class="btn btn-primary" onClick={start} disabled={!probe || !portalSelected || stopping}>
              {stopping ? <><span class="spinner" /> Preparing...</> : 'Start Karma'}
            </button>
          ) : (
            <button class="btn btn-danger" onClick={stop}>
              Stop Karma
            </button>
          )}
        </div>
      </section>

      {lastPassword ? (
        <section class="glass-card card-body reveal credential-hero">
          <div class="section-head">
            <h3 class="section-title">Latest Captured Credential</h3>
            <span class={`badge ${verified ? 'ok' : ''}`}>
              {verified ? 'Verified' : 'Unverified'}
            </span>
          </div>
          <div class="credential-value">{lastPassword.password}</div>
        </section>
      ) : running ? (
        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">Waiting for credentials</h3>
            <span class="badge"><span class="spinner" /> Listening</span>
          </div>
          <div class="section-note">
            Captive portal is live. The first password a victim submits will appear here.
          </div>
        </section>
      ) : null}

      {passwords.length > 0 ? (
        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">Capture History</h3>
            <span class="badge">{passwords.length}</span>
          </div>
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Password</th>
                </tr>
              </thead>
              <tbody>
                {passwords.map((pw, i) => (
                  <tr key={pw.id}>
                    <td>{passwords.length - i}</td>
                    <td>
                      {(pw.fields && pw.fields.length) ? pw.fields.map((f) => (
                        <div key={f.key}><span class="kv-key">{f.key}:</span> {f.value}</div>
                      )) : pw.password}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {clients.length > 0 ? (
        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">Connected Clients</h3>
            <span class={`badge ${clients.length > 0 ? 'ok' : ''}`}>{clients.length}</span>
          </div>
          <ul class="observer-clients">
            {clients.map((mac) => (
              <li class="observer-client" key={mac}>{mac}</li>
            ))}
          </ul>
        </section>
      ) : null}
    </Layout>
  );
}
