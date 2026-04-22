import { route } from 'preact-router';
import { api } from '../api';
import { getState } from '../store';
import { showToast } from '../components/Toast';
import { quickActionById } from '../quickActions';

const MODULES = [
  { id: 'scan', title: 'Scan', icon: 'wifi', path: '/scan' },
  { id: 'attacks', title: 'Attacks', icon: 'radar', path: '/global' },
  { id: 'observer', title: 'Observer', icon: 'eye', path: '/sniffer' },
  { id: 'wardrive', title: 'Wardrive', icon: 'map', path: '/wardrive' },
  { id: 'bluetooth', title: 'Bluetooth', icon: 'bt', path: '/bluetooth' },
  { id: 'data', title: 'Data', icon: 'disk', path: '/sddata' },
];

function Glyph({ name }) {
  const common = {
    width: 18,
    height: 18,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.9,
    strokeLinecap: 'round',
    strokeLinejoin: 'round',
    class: 'glyph-svg',
    'aria-hidden': 'true',
  };

  const icons = {
    wifi: (
      <svg {...common}>
        <path d="M3 9a14.5 14.5 0 0 1 18 0" />
        <path d="M6.5 12.5a9.5 9.5 0 0 1 11 0" />
        <path d="M10.2 16a4.2 4.2 0 0 1 3.6 0" />
        <circle cx="12" cy="19.2" r="1.2" fill="currentColor" stroke="none" />
      </svg>
    ),
    alert: (
      <svg {...common}>
        <path d="M12 4 3.8 19h16.4z" />
        <path d="M12 9v5" />
        <circle cx="12" cy="17" r="1" fill="currentColor" stroke="none" />
      </svg>
    ),
    portal: (
      <svg {...common}>
        <circle cx="12" cy="12" r="8" />
        <circle cx="12" cy="12" r="4" />
      </svg>
    ),
    ap: (
      <svg {...common}>
        <rect x="5" y="7" width="14" height="10" rx="3" />
        <path d="M9 12h6" />
      </svg>
    ),
    eye: (
      <svg {...common}>
        <path d="M2.8 12s3.4-6 9.2-6 9.2 6 9.2 6-3.4 6-9.2 6-9.2-6-9.2-6Z" />
        <circle cx="12" cy="12" r="2.2" />
      </svg>
    ),
    stop: (
      <svg {...common}>
        <rect x="6.5" y="6.5" width="11" height="11" rx="2.4" />
      </svg>
    ),
    radar: (
      <svg {...common}>
        <circle cx="12" cy="12" r="8" />
        <circle cx="12" cy="12" r="4" />
        <path d="m12 12 5.5-2.5" />
      </svg>
    ),
    map: (
      <svg {...common}>
        <path d="m4 7 5-2 6 2 5-2v12l-5 2-6-2-5 2z" />
        <path d="M9 5v12M15 7v12" />
      </svg>
    ),
    bt: (
      <svg {...common}>
        <path d="m12 4 5 4-5 4 5 4-5 4V4Z" />
        <path d="m7 8 10 8M7 16 17 8" />
      </svg>
    ),
    disk: (
      <svg {...common}>
        <rect x="4.2" y="4.2" width="15.6" height="15.6" rx="2.6" />
        <circle cx="12" cy="12" r="2.4" />
      </svg>
    ),
  };

  return icons[name] || icons.wifi;
}

function formatGps(st) {
  if (!st.gpsFix) return 'no fix';
  return `${st.gpsLat.toFixed(5)}, ${st.gpsLon.toFixed(5)}`;
}

function formatLastNet(st) {
  if (!st.networks.length) return '-';
  const strongest = st.networks.reduce((best, n) => (n.rssi > best.rssi ? n : best), st.networks[0]);
  return `${strongest.ssid || '[Hidden]'} ${strongest.rssi} dBm`;
}

function freeRatio(st) {
  if (st.sdTotalGb <= 0 || st.sdFreeGb < 0) return 0;
  return Math.max(0, Math.min(1, st.sdFreeGb / st.sdTotalGb));
}

export function Home() {
  const st = getState();
  const quick = (st.quickActions || ['scan', 'blackout', 'stop']).map((id) => quickActionById(id));

  async function triggerQuickAction(item) {
    if (item.id === 'scan') {
      route('/scan');
      return;
    }
    if (item.id === 'stop') {
      await api.stop();
      showToast('Stop signal sent', 'warning');
      return;
    }
    if (item.id === 'blackout') {
      const res = await api.blackout();
      if (res.ok) showToast('Blackout started', 'success');
      else showToast(res.error || 'Blackout failed', 'error');
      return;
    }
    if (item.id === 'observer') {
      route('/sniffer');
      return;
    }
    if (item.id === 'deauth') {
      route('/deauth');
      return;
    }
    if (item.id === 'eviltwin') {
      route('/eviltwin');
      return;
    }
    if (item.id === 'mitm') {
      const res = await api.mitm();
      if (res.ok) showToast('MITM started', 'success');
      else showToast(res.error || 'MITM failed', 'error');
      return;
    }
    if (item.id === 'nmap') {
      const res = await api.nmap();
      if (res.ok) showToast('Nmap started', 'success');
      else showToast(res.error || 'Nmap failed', 'error');
      return;
    }
    if (item.id === 'arp') {
      const res = await api.arp();
      if (res.ok) showToast('ARP started', 'success');
      else showToast(res.error || 'ARP failed', 'error');
    }
  }

  const ratio = freeRatio(st);
  const ringDeg = Math.round(ratio * 360);
  const sdLabel = st.sdTotalGb > 0 ? `${st.sdFreeGb}/${st.sdTotalGb} GB free` : 'n/a';

  return (
    <section class="module-page reveal">
      <section class="glass-card card-body">
        <div class="section-head">
          <h3 class="section-title">Modules</h3>
        </div>
        <div class="module-grid">
          {MODULES.map((module) => (
            <button key={module.id} class="module-tile action-accent-cyan" onClick={() => route(module.path)}>
              <span class="module-icon plain"><Glyph name={module.icon} /></span>
              <span class="module-tile-title">{module.title}</span>
            </button>
          ))}
        </div>
      </section>

      <section class="glass-card card-body">
        <div class="section-head">
          <h3 class="section-title">Quick Actions</h3>
        </div>
        <div class="quick-grid quick-grid-compact">
          {quick.map((item) => (
            <button key={item.id} class={`quick-action-mini action-accent-${item.id === 'stop' ? 'red' : 'cyan'}`} onClick={() => triggerQuickAction(item)}>
              <span class="action-icon plain"><Glyph name={item.icon} /></span>
              <span class="action-title">{item.label}</span>
            </button>
          ))}
        </div>
      </section>

      <section class="glass-card card-body">
        <div class="section-head">
          <h3 class="section-title">Stats</h3>
        </div>
        <div class="stats-grid stats-grid-compact">
          <article class="stat-card">
            <div class="stat-label">Handshakes</div>
            <div class="stat-value">{st.handshakeLoading ? '...' : st.handshakeCount}</div>
          </article>
          <article class="stat-card">
            <div class="stat-label">GPS</div>
            <div class="stat-value stat-value-mini">{formatGps(st)}</div>
          </article>
          <article class="stat-card">
            <div class="stat-label">Last Net</div>
            <div class="stat-value stat-value-mini">{formatLastNet(st)}</div>
          </article>
          <article class="stat-card stat-card-ring">
            <div class="stat-label">SD Space</div>
            <div class="ring-wrap" style={`--ring-deg:${ringDeg}deg`}>
              <div class="ring-core" />
            </div>
            <div class="stat-value stat-value-mini">{sdLabel}</div>
          </article>
        </div>
      </section>
    </section>
  );
}
