import { route } from 'preact-router';
import { Layout } from '../components/Layout';

const TILES = [
  {
    id: 'listen',
    title: 'Listen',
    note: 'RX with live waterfall and signal capture',
    path: '/subghz/listen',
  },
  {
    id: 'transmit',
    title: 'Transmit',
    note: 'Replay a stored signal by index',
    path: '/subghz/transmit',
  },
  {
    id: 'manage',
    title: 'Manage',
    note: 'View, delete, import/export signals on SD',
    path: '/subghz/manage',
  },
  {
    id: 'jammer',
    title: 'Jammer',
    note: 'Continuous TX on a chosen frequency',
    path: '/subghz/jammer',
  },
  {
    id: 'tesla',
    title: 'Tesla',
    note: '315 MHz OOK charge-port opener',
    path: '/subghz/tesla',
  },
];

export function SubGhz() {
  return (
    <Layout title="SubGHZ" back="/">
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Modules</h3>
        </div>
        <div class="quick-grid">
          {TILES.map((tile) => (
            <button
              key={tile.id}
              class="action-card action-card-text-only action-accent-magenta"
              onClick={() => route(tile.path)}
            >
              <span class="action-title">{tile.title}</span>
              <span class="action-note">{tile.note}</span>
            </button>
          ))}
        </div>
      </section>
    </Layout>
  );
}
