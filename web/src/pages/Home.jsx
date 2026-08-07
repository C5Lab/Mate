import { route } from 'preact-router';
import { api } from '../api';
import { getState } from '../store';
import { showToast } from '../components/Toast';

const MODULES = [
  { id: 'scan', title: 'Scan APs', note: 'WiFi scan', icon: 'wifi', path: '/scan', accent: 'blue' },
  { id: 'attacks', title: 'Attacks', note: 'Controls', icon: 'radar', path: '/global', accent: 'red' },
  { id: 'detector', title: 'Detector', note: 'Deauth watch', icon: 'alert', path: '/detector', accent: 'red' },
  { id: 'subghz', title: 'SubGHZ', note: 'RF tools', icon: 'radio', path: '/subghz', accent: 'violet' },
  { id: 'observer', title: 'Observer', note: 'Telemetry', icon: 'eye', path: '/sniffer', accent: 'slate' },
  { id: 'wardrive', title: 'Wardrive', note: 'GPS logs', icon: 'map', path: '/wardrive', accent: 'yellow' },
  { id: 'mesh', title: 'Mesh Recon', note: 'Zigbee/802.15.4', icon: 'mesh', path: '/mesh', accent: 'violet' },
  { id: 'bluetooth', title: 'Bluetooth', note: 'BT scan', icon: 'bt', path: '/bluetooth', accent: 'green' },
  { id: 'data', title: 'Data', note: 'Files', icon: 'disk', path: '/sddata', accent: 'cyan' },
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
    radio: (
      <svg {...common}>
        <circle cx="12" cy="12" r="2" fill="currentColor" stroke="none" />
        <path d="M8.5 8.5a5 5 0 0 0 0 7M15.5 8.5a5 5 0 0 1 0 7" />
        <path d="M5.5 5.5a9 9 0 0 0 0 13M18.5 5.5a9 9 0 0 1 0 13" />
      </svg>
    ),
    mesh: (
      <svg {...common}>
        <circle cx="12" cy="5" r="2.2" />
        <circle cx="5" cy="18" r="2.2" />
        <circle cx="19" cy="18" r="2.2" />
        <path d="M10.7 6.7 6.3 16.3M13.3 6.7 17.7 16.3M7.2 18h9.6" />
      </svg>
    ),
  };

  return icons[name] || icons.wifi;
}

function formatGps(st) {
  if (!st.gpsFix) return 'no fix';
  return `${st.gpsLat.toFixed(5)}, ${st.gpsLon.toFixed(5)}`;
}

function operationLabel(status) {
  const labels = {
    idle: 'Chillin',
    scan: 'AP Scan',
    scanning: 'AP Scan',
    deauth: 'Deauth',
    blackout: 'Blackout',
    handshaker: 'Handshake Capture',
    handshake: 'Handshake Capture',
    sniffer: 'Observer',
    mitm: 'MITM',
    nmap: 'Nmap',
    arp: 'ARP',
    karma: 'Karma',
    portal: 'Portal',
    subghz: 'SubGHz',
    subghz_listen: 'SubGHz Listen',
    subghz_jam: 'SubGHz Jam',
    wardrive: 'Wardrive',
    wardrive_run: 'Wardrive',
    antisurv: 'Anti-Surveillance',
    antisurv_run: 'Anti-Surveillance',
    zig_recon: 'Mesh Recon',
  };
  if (labels[status]) return labels[status];
  if (!status) return 'Chillin';
  /* Prettify any unmapped device-state string, e.g. "listing_wardrive"
   * -> "Listing Wardrive", instead of leaking the raw token. */
  return String(status).replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function operationMeta(st) {
  if (st.status === 'idle') return 'Ready';
  if (st.status === 'scanning') return `${st.scanCount || st.networks.length || 0} APs discovered`;
  if (st.status === 'wardrive' || st.status === 'wardrive_run') {
    const s = st.wardrive && st.wardrive.stats;
    return s ? `${s.nets} nets · ${s.bt} BT · ${Math.round(s.dist)} m` : 'Waiting for GPS fix';
  }
  if (st.packetCount) return `${st.packetCount} packets captured`;
  return 'Operation running';
}

function sdLabelFor(st) {
  if (st.sdPresent === 1) return 'SD OK';
  if (st.sdPresent === 0) return 'No SD';
  return '...';
}

export function Home() {
  const st = getState();

  async function stopOperation() {
    await api.stop();
    showToast('Stop signal sent', 'warning');
  }

  const ringDeg = st.sdPresent === 1 ? 360 : 0;
  const sdLabel = sdLabelFor(st);
  const isBusy = st.status && st.status !== 'idle';

  return (
    <section class="module-page reveal">
      <section class={`operation-focus glass-card ${isBusy ? 'active' : ''}`}>
        <div class={`operation-icon accent-${isBusy ? 'green' : 'slate'}`}>
          <Glyph name={isBusy ? 'wifi' : 'radar'} />
        </div>
        <div class="operation-inline">
          <div class="eyebrow">Current Operation</div>
          <div class="operation-name">{operationLabel(st.status)}</div>
          <div class="operation-caption">{operationMeta(st)}</div>
        </div>
        {isBusy && (
          <button class="btn btn-danger operation-stop" onClick={stopOperation}>
            <Glyph name="stop" />
            Stop
          </button>
        )}
      </section>

      <section class="glass-card card-body">
        <div class="section-head">
          <h3 class="section-title">Monster Stats</h3>
        </div>
        <div class="stats-strip monster-stats">
          <article class="stat-card accent-yellow">
            <Glyph name="radar" />
            <div class="stat-value">{st.handshakeLoading ? '...' : st.handshakeCount}</div>
            <div class="stat-label">Handshakes</div>
          </article>
          <article class="stat-card accent-blue">
            <Glyph name="map" />
            <div class="stat-value stat-value-mini">{formatGps(st)}</div>
            <div class="stat-label">GPS</div>
          </article>
          <article class="stat-card stat-card-ring accent-violet">
            <div class="ring-wrap" style={`--ring-deg:${ringDeg}deg`}>
              <div class="ring-core" />
            </div>
            <div class="stat-value stat-value-mini">{sdLabel}</div>
            <div class="stat-label">SD Card</div>
          </article>
        </div>
      </section>

      <section class="glass-card card-body">
        <div class="section-head">
          <h3 class="section-title">Modules</h3>
        </div>
        <div class="module-list">
          {MODULES.map((module) => (
            <button key={module.id} class={`module-entry accent-${module.accent}`} onClick={() => route(module.path)}>
              <span class="module-icon"><Glyph name={module.icon} /></span>
              <span class="module-copy">
                <span class="module-title">{module.title}</span>
                <span class="module-note">{module.note}</span>
              </span>
              <span class="module-arrow">›</span>
            </button>
          ))}
        </div>
      </section>
    </section>
  );
}
