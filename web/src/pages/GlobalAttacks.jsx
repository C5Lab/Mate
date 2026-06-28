import { route } from 'preact-router';
import { useEffect, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { api } from '../api';
import { getState } from '../store';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';

const ACTIONS = [
  {
    id: 'blackout',
    title: 'Blackout',
    note: 'Mass deauth wave on selected targets',
    available: true,
    run: async () => api.blackout(),
  },
  {
    id: 'handshaker',
    title: 'Handshaker',
    note: 'Capture handshake packets',
    available: true,
    run: async () => api.handshake(),
  },
  {
    id: 'portal',
    title: 'Portal',
    note: 'Open captive portal with custom SSID and SD template',
    available: true,
    route: '/portal',
  },
  {
    id: 'snifferdog',
    title: 'SnifferDog',
    note: 'Observer mode with AP/client snapshots',
    available: true,
    run: async () => api.sniffer(),
    routeOnSuccess: '/sniffer',
  },
  {
    id: 'beaconspam',
    title: 'Beacon Spam',
    note: 'Unavailable in current firmware API',
    available: false,
  },
  {
    id: 'karma',
    title: 'Karma',
    note: 'Open dedicated Karma module',
    available: true,
    route: '/karma',
  },
];

export function GlobalAttacks() {
  const [activeLabel, setActiveLabel] = useState('None');
  const st = getState();

  useEffect(() => wsAddListener((msg) => {
    if (msg.type === 'attack_started' && msg.attack) setActiveLabel(msg.attack);
    if (msg.type === 'attack_stopped') setActiveLabel('None');
  }), []);

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
              class={`action-card action-card-text-only ${action.available ? 'action-accent-magenta' : 'action-accent-red'}`}
              onClick={() => triggerAction(action)}
            >
              <span class="action-title">{action.title}</span>
              <span class="action-note">{action.note}</span>
            </button>
          ))}
        </div>

        <button class="btn btn-danger btn-block" onClick={stopAll}>
          Stop Global Operations
        </button>
      </section>
    </Layout>
  );
}
