import Router from 'preact-router';
import { useEffect, useState } from 'preact/hooks';
import { api } from './api';
import { wsAddListener, wsConnect } from './ws';
import { getState, setQuickActions, setState, subscribe } from './store';
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

export function App() {
  const [, forceUpdate] = useState(0);
  const [settingsOpen, setSettingsOpen] = useState(false);

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
    const pollStatusId = setInterval(syncStatus, 12000);
    const pollDashId = setInterval(syncDashboard, 12000);

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
      }

      if (msg.type === 'attack_stopped') {
        setState({ status: 'idle' });
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
    });

    const removeSub = subscribe(() => forceUpdate((n) => n + 1));

    return () => {
      clearInterval(pollStatusId);
      clearInterval(pollDashId);
      removeWs();
      removeSub();
    };
  }, []);

  const st = getState();
  const heapMb = (st.heapFree / (1024 * 1024)).toFixed(1);
  const wifiLabel = st.staConnected ? (st.staSsid || 'Connected') : 'Disconnected';

  function updateQuickAction(slot, value) {
    const next = [...(st.quickActions || ['scan', 'blackout', 'stop'])];
    next[slot] = value;
    setQuickActions(next);
  }

  return (
    <div class="app-shell">
      <header class="glass-card topbar reveal">
        <div class="topbar-main compact">
          <div class="topbar-copy">
            <h1 class="brand-logo">LAB5</h1>
            <div class="brand-subtitle">{st.deviceName}</div>
          </div>
          <button class="settings-btn compact" onClick={() => setSettingsOpen(true)}>
            ⚙
          </button>
        </div>

        <div class="topbar-metrics compact">
          <div class="chip compact chip-graphic">
            <span class={`chip-dot ${st.c5Connected ? 'ok' : 'bad'}`} />
            <span class="chip-glyph">C5</span>
            <span class="chip-value">{st.c5Connected ? 'Connected' : 'No Link'}</span>
          </div>

          <div class="chip compact chip-graphic">
            <span class="chip-glyph">AP</span>
            <span class="chip-value">{st.apClients} clients</span>
          </div>

          <div class="chip compact chip-graphic">
            <span class="chip-glyph">RAM</span>
            <span class="chip-value">{heapMb} MB</span>
          </div>

          <div class="chip compact chip-graphic">
            <span class="chip-glyph chip-glyph-icon">
              <WifiMetricIcon connected={!!st.staConnected} />
            </span>
            <span class="chip-value">{wifiLabel}</span>
          </div>
        </div>
      </header>

      <main class="page-shell">
        <Router>
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

      <ToastContainer />
    </div>
  );
}
