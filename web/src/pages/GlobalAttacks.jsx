import { route } from 'preact-router';
import { useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { AttackMonitor } from '../components/AttackMonitor';
import { api } from '../api';
import { getState } from '../store';
import { showToast } from '../components/Toast';

const ACTIONS = [
  {
    id: 'blackout',
    title: 'Blackout',
    icon: 'alert',
    note: 'Mass deauth wave on selected targets',
    available: true,
    run: async () => api.blackout(),
  },
  {
    id: 'handshaker',
    title: 'Handshaker',
    icon: 'handshake',
    note: 'Capture handshake packets',
    available: true,
    run: async () => api.handshake(),
  },
  {
    id: 'portal',
    title: 'Portal',
    icon: 'portal',
    note: 'Launch portal-based Evil Twin flow',
    available: true,
    route: '/eviltwin',
  },
  {
    id: 'snifferdog',
    title: 'SnifferDog',
    icon: 'eye',
    note: 'Observer mode with AP/client snapshots',
    available: true,
    run: async () => api.sniffer(),
    routeOnSuccess: '/sniffer',
  },
  {
    id: 'beaconspam',
    title: 'Beacon Spam',
    icon: 'radar',
    note: 'Unavailable in current firmware API',
    available: false,
  },
  {
    id: 'karma',
    title: 'Karma',
    icon: 'bolt',
    note: 'Open dedicated Karma module',
    available: true,
    route: '/karma',
  },
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
    alert: (
      <svg {...common}>
        <path d="M12 4 3.8 19h16.4z" />
        <path d="M12 9v5" />
        <circle cx="12" cy="17" r="1" fill="currentColor" stroke="none" />
      </svg>
    ),
    handshake: (
      <svg {...common}>
        <path d="M7 12.5 4.8 10.3a2 2 0 0 1 2.8-2.8l2.3 2.3" />
        <path d="m17 11.5 2.2 2.2a2 2 0 0 1-2.8 2.8l-2.3-2.3" />
        <path d="m9 10 2.2 2.2a1.8 1.8 0 0 0 2.6 0l2.2-2.2" />
      </svg>
    ),
    portal: (
      <svg {...common}>
        <circle cx="12" cy="12" r="8" />
        <circle cx="12" cy="12" r="4" />
      </svg>
    ),
    eye: (
      <svg {...common}>
        <path d="M2.8 12s3.4-6 9.2-6 9.2 6 9.2 6-3.4 6-9.2 6-9.2-6-9.2-6Z" />
        <circle cx="12" cy="12" r="2.2" />
      </svg>
    ),
    radar: (
      <svg {...common}>
        <circle cx="12" cy="12" r="8" />
        <circle cx="12" cy="12" r="4" />
        <path d="m12 12 5.5-2.5" />
      </svg>
    ),
    bolt: (
      <svg {...common}>
        <path d="M13 3 6 13h5l-1 8 8-12h-5z" />
      </svg>
    ),
  };

  return icons[name] || icons.alert;
}

export function GlobalAttacks() {
  const [activeLabel, setActiveLabel] = useState('None');
  const st = getState();

  async function triggerAction(action) {
    if (!action.available) {
      showToast('This command is not exposed by current firmware', 'warning');
      return;
    }

    if (action.route) {
      route(action.route);
      return;
    }

    if (action.requiresSelection && !st.selected.size) {
      showToast('Select targets first in WiFi Scan', 'warning');
      route('/scan');
      return;
    }

    try {
      if (st.selected.size) {
        await api.select(Array.from(st.selected));
      }

      const res = await action.run();
      if (res.ok) {
        setActiveLabel(action.title);
        showToast(`${action.title} started`, 'success');
        if (action.routeOnSuccess) {
          route(action.routeOnSuccess);
        }
      } else {
        showToast(res.error || `${action.title} failed`, 'error');
      }
    } catch (e) {
      showToast(`${action.title} failed`, 'error');
    }
  }

  async function stopAll() {
    await api.stop();
    setActiveLabel('None');
    showToast('Stop signal sent', 'warning');
  }

  return (
    <Layout
      title="Attacks"
      back="/"
    >
      <section class="glass-card card-body reveal">
        <div class="kv">
          <div class="kv-row">
            <span class="kv-key">Active command</span>
            <span class="kv-val">{activeLabel}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">Selected targets</span>
            <span class="kv-val">{st.selected.size}</span>
          </div>
        </div>

        <div class="quick-grid">
          {ACTIONS.map((action) => (
            <button
              key={action.id}
              class={`action-card ${action.available ? 'action-accent-magenta' : 'action-accent-red'}`}
              onClick={() => triggerAction(action)}
            >
              <span class="action-icon plain"><Glyph name={action.icon} /></span>
              <span class="action-title">{action.title}</span>
              <span class="action-note">{action.note}</span>
            </button>
          ))}
        </div>

        <button class="btn btn-danger btn-block" onClick={stopAll}>
          Stop Global Operations
        </button>
      </section>

      <AttackMonitor
        title="Global Operations Log"
        onEvent={(msg) => {
          if (msg.type === 'attack_started' && msg.attack) {
            setActiveLabel(msg.attack);
          }
          if (msg.type === 'attack_stopped') {
            setActiveLabel('None');
          }
        }}
      />
    </Layout>
  );
}
