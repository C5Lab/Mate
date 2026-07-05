import Router from 'preact-router';
import { useEffect, useRef, useState } from 'preact/hooks';
import { api } from './api';
import { wsAddListener, wsConnect } from './ws';
import {
  addArpHost,
  clearArpHosts,
  getState,
  setArpHosts,
  setQuickActions,
  setState,
  subscribe,
  wardriveReset,
  wardrivePatch,
  antisurvReset,
  antisurvPatch,
} from './store';
import { ingestWardriveLine } from './wardriveParse';
import { ToastContainer } from './components/Toast';
import { QUICK_ACTION_OPTIONS } from './quickActions';

import { Home } from './pages/Home';
import { Scan } from './pages/Scan';
import { Deauth } from './pages/Deauth';
import { EvilTwin } from './pages/EvilTwin';
import { RogueAP } from './pages/RogueAP';
import { SaeOverflow } from './pages/SaeOverflow';
import { Handshaker } from './pages/Handshaker';
import { Sniffer } from './pages/Sniffer';
import { GlobalAttacks } from './pages/GlobalAttacks';
import { SDData } from './pages/SDData';
import { Bluetooth } from './pages/Bluetooth';
import { Wardrive } from './pages/Wardrive';
import { Karma } from './pages/Karma';
import { DeauthDetector } from './pages/DeauthDetector';
import { Portal } from './pages/Portal';
import { SubGhz } from './pages/SubGhz';
import { SubGhzListen } from './pages/subghz/Listen';
import { SubGhzTransmit } from './pages/subghz/Transmit';
import { SubGhzManage } from './pages/subghz/Manage';
import { SubGhzJammer } from './pages/subghz/Jammer';
import { SubGhzTesla } from './pages/subghz/Tesla';

function normalizeStatus(value) {
  if (!value) return 'idle';
  if (value === 'scan') return 'scanning';
  return value;
}

function WifiMetricIcon({ connected }) {
  return (
    <svg class={`metric-icon ${connected ? 'ok' : 'bad'}`} viewBox="0 0 24 24" aria-hidden="true">
      <path d="M3 9a14.5 14.5 0 0 1 18 0" />
      <path d="M6.5 12.5a9.5 9.5 0 0 1 11 0" />
      <path d="M10.2 16a4.2 4.2 0 0 1 3.6 0" />
      <circle cx="12" cy="19.2" r="1.2" />
    </svg>
  );
}

function SettingsIcon() {
  return (
    <svg class="metric-icon" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 8.2a3.8 3.8 0 1 1 0 7.6 3.8 3.8 0 0 1 0-7.6Z" />
      <path d="m19.4 15-.9 1.6 1 2.1-2 2-2.1-1-1.7 1H10.3l-1.7-1-2.1 1-2-2 1-2.1L4.6 15V9l.9-1.6-1-2.1 2-2 2.1 1 1.7-1h3.4l1.7 1 2.1-1 2 2-1 2.1.9 1.6v6Z" />
    </svg>
  );
}

/* Bump this on every web change so the footer confirms which build is loaded.
 * If the footer version doesn't match the latest, the browser is serving a
 * cached/stale app.js (hard-refresh or open in a private tab). */
export const WEB_VERSION = '0011';

export function App() {
  const [, forceUpdate] = useState(0);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const syncStatusRef = useRef(null);

  useEffect(() => {
    wsConnect();

    const syncStatus = async () => {
      try {
        const data = await api.status();
        if (!data?.ok) return;

        setState({
          status: normalizeStatus(data.state),
          scanCount: data.scan_count || 0,
          packetCount: data.packet_count || 0,
          c5Connected: !!data.c5_connected,
          staConnected: !!data.sta_connected,
          staSsid: data.sta_ssid || '',
          apClients: data.ap_clients || 0,
          heapFree: data.heap_free || 0,
          heapInternal: data.heap_internal || 0,
        });

        /* Reconcile the wardrive/anti-surv run flags from the authoritative
         * device state. The WS attack_started/stopped events are the fast
         * path but a single dropped frame (or a page reload mid-run) would
         * otherwise leave the Engine UI out of sync with the top menu. */
        const s = getState();
        const wdRun = data.state === 'wardrive_run';
        const asRun = data.state === 'antisurv_run';
        if (s.wardrive.running !== wdRun) {
          if (wdRun) wardriveReset({ running: true, gps: 'waiting' });
          else wardrivePatch({ running: false, gps: 'idle' });
        }
        if (s.antisurv.running !== asRun) antisurvPatch({ running: asRun });
      } catch (e) {
        /* ignore status polling errors */
      }
    };

    const syncDashboard = async () => {
      try {
        const data = await api.dashboard();
        if (!data?.ok) return;
        setState({
          c5Connected: !!data.c5_connected,
          apClients: data.ap_clients || 0,
          heapFree: data.heap_free || 0,
          heapInternal: data.heap_internal || 0,
          handshakeCount: data.handshake_count || 0,
          handshakeLoading: !!data.handshake_loading,
          gpsFix: !!data.gps_fix,
          gpsLat: data.gps_lat || 0,
          gpsLon: data.gps_lon || 0,
          sdFreeGb: data.sd_free_gb ?? -1,
          sdTotalGb: data.sd_total_gb ?? -1,
          staConnected: !!data.sta_connected,
          staSsid: data.sta_ssid || '',
        });
      } catch (e) {
        /* ignore dashboard polling errors */
      }
    };

    syncStatus();
    syncDashboard();
    /* Poll fairly briskly: /api/status just reads the cached FSM state (no
     * UART round-trip), and the WS attack_stopped event is unreliable here, so
     * this poll is what clears the top "Current Operation" tile after an attack
     * ends. 12s felt like a ~20s lag; 3s keeps it snappy. */
    syncStatusRef.current = syncStatus;
    const pollStatusId = setInterval(syncStatus, 3000);

    const removeWs = wsAddListener((msg) => {
      const st = getState();

      if (msg.type === 'ws_connected') {
        setState({ wsConnected: true });
      }

      if (msg.type === 'ws_disconnected') {
        setState({ wsConnected: false });
      }

      if (msg.type === 'scan_network') {
        const exists = st.networks.some((n) => n.index === msg.network.index);
        if (!exists) {
          const next = [...st.networks, msg.network];
          setState({ networks: next, scanCount: next.length });
        }
      }

      if (msg.type === 'scan_complete') {
        setState({ status: 'idle', lastScanAt: Date.now(), scanCount: st.networks.length });
      }

      if (msg.type === 'attack_started') {
        setState({ status: normalizeStatus(msg.attack) });
        /* Only (re)initialize if not already running. This frame can arrive
         * AFTER the one-shot "GPS fix obtained" line and the first CSV rows
         * (WS vs uart_line are separate transports), so blindly resetting
         * would wipe the fix state + table and strand the badge on
         * "Waiting for GPS fix". The optimistic startRun() already armed it. */
        if (msg.attack === 'wardrive' && !st.wardrive.running) {
          wardriveReset({ running: true, gps: 'waiting' });
        } else if (msg.attack === 'antisurv' && !st.antisurv.running) {
          antisurvReset({ running: true });
        }
      }

      if (msg.type === 'attack_stopped') {
        setState({ status: 'idle' });
        if (st.wardrive.running) wardrivePatch({ running: false, gps: 'idle' });
        if (st.antisurv.running) antisurvPatch({ running: false });
      }

      if (msg.type === 'sniffer_count') {
        setState({ packetCount: msg.count || 0 });
      }

      if (msg.type === 'wifi_connected') {
        setState({ staConnected: true });
      }

      if (msg.type === 'wifi_disconnected' || msg.type === 'wifi_connect_failed') {
        setState({ staConnected: false, staSsid: '' });
      }

      /* Preferred fast path: the firmware sends a single structured
       * `arp_hosts` event when `list_hosts` finishes. One frame is much
       * harder to lose than the original 7-line raw burst. */
      if (msg.type === 'arp_hosts') {
        setArpHosts(msg.hosts || [], Date.now());
      }

      /* Fallback: capture `list_hosts` raw lines globally in case the
       * structured event got dropped (e.g. WS still re-handshaking when
       * the burst arrives). The Scan ARP panel reads from
       * `getState().arpHosts` regardless of which page is mounted.
       * JanOS prints each host as:
       *   "  192.168.0.1  ->  AC:22:05:84:4F:CC  [ARP]"
       *   "  192.168.0.247  ->  (MAC unknown)  [ICMP]"
       * We skip the ICMP-only rows because arp_ban needs a usable MAC. */
      if (msg.type === 'uart_line' && typeof msg.data === 'string') {
        const line = msg.data;
        // Wardrive / anti-surveillance stream (CSV rows, stats, GPS, followers).
        if (ingestWardriveLine(line)) return;
        if (line.includes('=== Discovered Hosts ===')) {
          clearArpHosts();
        } else {
          const m = line.match(
            /^\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*->\s*([0-9A-Fa-f:]{17})(?:\s+\[[^\]]+\])?\s*$/,
          );
          if (m) addArpHost(m[1], m[2]);
        }
      }
    });

    const removeSub = subscribe(() => forceUpdate((n) => n + 1));

    return () => {
      clearInterval(pollStatusId);
      removeWs();
      removeSub();
    };
  }, []);

  const st = getState();
  const wifiLabel = st.staConnected ? (st.staSsid || 'Connected') : 'Disconnected';

  function updateQuickAction(slot, value) {
    const next = [...(st.quickActions || ['scan', 'blackout', 'stop'])];
    next[slot] = value;
    setQuickActions(next);
  }

  return (
    <div class="app-shell">
      <header class="glass-card topbar reveal">
        <div class="topbar-main">
          <div class="topbar-copy">
            <div class="eyebrow">Dashboard</div>
            <h1 class="brand-logo">JanOS</h1>
          </div>
          <button class="settings-btn" onClick={() => setSettingsOpen(true)} aria-label="Open settings">
            <SettingsIcon />
          </button>
        </div>

        <div class="topbar-metrics">
          <div class="chip chip-graphic">
            <span class={`chip-dot ${st.c5Connected ? 'ok' : 'bad'}`} />
            <span class="chip-glyph">C5</span>
            <span class="chip-value">{st.c5Connected ? 'Connected' : 'No Link'}</span>
          </div>

          <div class="chip chip-graphic">
            <span class="chip-glyph">AP</span>
            <span class="chip-value">{st.apClients} clients</span>
          </div>

          <div class="chip chip-graphic">
            <span class="chip-glyph chip-glyph-icon">
              <WifiMetricIcon connected={!!st.staConnected} />
            </span>
            <span class="chip-value">{wifiLabel}</span>
          </div>
        </div>
      </header>

      <main class="page-shell">
        <Router onChange={() => { window.scrollTo(0, 0); syncStatusRef.current?.(); }}>
          <Home path="/" />
          <Scan path="/scan" />
          <Deauth path="/deauth" />
          <EvilTwin path="/eviltwin" />
          <RogueAP path="/rogueap" />
          <SaeOverflow path="/sae" />
          <Handshaker path="/handshaker" />
          <Sniffer path="/sniffer" />
          <Sniffer path="/observer" />
          <GlobalAttacks path="/global" />
          <SDData path="/sddata" />
          <Bluetooth path="/bluetooth" />
          <Wardrive path="/wardrive" />
          <Karma path="/karma" />
          <Portal path="/portal" />
          <DeauthDetector path="/detector" />
          <SubGhz path="/subghz" />
          <SubGhzListen path="/subghz/listen" />
          <SubGhzTransmit path="/subghz/transmit" />
          <SubGhzManage path="/subghz/manage" />
          <SubGhzJammer path="/subghz/jammer" />
          <SubGhzTesla path="/subghz/tesla" />
        </Router>
      </main>

      {settingsOpen ? (
        <div class="settings-overlay" onClick={() => setSettingsOpen(false)}>
          <section class="glass-card settings-panel" onClick={(e) => e.stopPropagation()}>
            <div class="section-head">
              <h3 class="section-title">Settings</h3>
              <button class="soft-btn" onClick={() => setSettingsOpen(false)}>Close</button>
            </div>
            <div class="field">
              <label class="field-label">Quick Action #1</label>
              <select class="select" value={st.quickActions?.[0] || 'scan'} onChange={(e) => updateQuickAction(0, e.target.value)}>
                {QUICK_ACTION_OPTIONS.map((opt) => <option key={opt.id} value={opt.id}>{opt.label}</option>)}
              </select>
            </div>
            <div class="field">
              <label class="field-label">Quick Action #2</label>
              <select class="select" value={st.quickActions?.[1] || 'blackout'} onChange={(e) => updateQuickAction(1, e.target.value)}>
                {QUICK_ACTION_OPTIONS.map((opt) => <option key={opt.id} value={opt.id}>{opt.label}</option>)}
              </select>
            </div>
            <div class="field">
              <label class="field-label">Quick Action #3</label>
              <select class="select" value={st.quickActions?.[2] || 'stop'} onChange={(e) => updateQuickAction(2, e.target.value)}>
                {QUICK_ACTION_OPTIONS.map((opt) => <option key={opt.id} value={opt.id}>{opt.label}</option>)}
              </select>
            </div>
          </section>
        </div>
      ) : null}

      <footer class="app-version">
        JanOS Web <span>v{WEB_VERSION}</span>
      </footer>

      <ToastContainer />
    </div>
  );
}
