import { route } from 'preact-router';
import { getState } from '../store';
import { api } from '../api';
import { showToast } from '../components/Toast';

const TILES = [
  { id: 'scan',    icon: '\u{1F4E1}', label: 'WiFi Scan',    color: 'var(--cyan)',    path: '/scan' },
  { id: 'deauth',  icon: '\u{1F4A5}', label: 'Deauth',       color: 'var(--red)',     path: '/deauth',    needSel: true },
  { id: 'evil',    icon: '\u{1F47B}', label: 'Evil Twin',     color: 'var(--orange)',  path: '/eviltwin',  needSel: true },
  { id: 'rogue',   icon: '\u{1F3AD}', label: 'Rogue AP',      color: 'var(--magenta)', path: '/rogueap' },
  { id: 'sae',     icon: '\u{1F513}', label: 'SAE Overflow',  color: 'var(--pink)',    path: '/sae',       needSel: true },
  { id: 'hs',      icon: '\u{1F91D}', label: 'Handshaker',    color: 'var(--green)',   path: '/handshaker' },
  { id: 'sniff',   icon: '\u{1F50D}', label: 'Network Observer', color: 'var(--cyan)', path: '/sniffer' },
  { id: 'stop',    icon: '\u{26D4}',  label: 'Stop All',      color: 'var(--red)',     action: 'stop' },
];

export function Home() {
  const st = getState();
  const hasSel = st.selected.size > 0;

  function handleTile(t) {
    if (t.action === 'stop') {
      api.stop();
      showToast('Stop sent', 'warning');
      return;
    }
    if (t.needSel && !hasSel) {
      showToast('Select networks first (Scan)', 'warning');
      return;
    }
    route(t.path);
  }

  return (
    <div>
      {st.networks.length > 0 && (
        <div class="sel-bar">
          <span class="sel-count">{st.selected.size} selected</span>
          <span style="font-size:11px;color:var(--muted)">
            of {st.networks.length} networks
          </span>
        </div>
      )}

      <div class="tiles">
        {TILES.map(t => (
          <div
            key={t.id}
            class={`tile ${t.id === 'stop' ? 'stop' : ''} ${t.needSel && !hasSel ? 'disabled' : ''}`}
            onClick={() => handleTile(t)}
          >
            <div class="icon" style={{ color: t.color }}>{t.icon}</div>
            <div class="label">{t.label}</div>
          </div>
        ))}
      </div>

      {st.networks.length > 0 && (
        <div class="panel">
          <div class="panel-header">
            Last scan: {st.networks.length} networks
          </div>
        </div>
      )}
    </div>
  );
}
