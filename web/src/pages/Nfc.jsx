import { route } from 'preact-router';
import { useEffect, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { api } from '../api';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';
import { waitForNfc } from '../nfcUtil';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const TILES = [
  {
    id: 'read',
    title: 'Read',
    note: 'Poll a card into the save slot',
    path: '/nfc/read',
  },
  {
    id: 'library',
    title: 'Library',
    note: 'Saved .nfc files on SD',
    path: '/nfc/library',
  },
];

const BUSES = [
  { id: 'i2c', label: 'I2C (Grove ST25)' },
  { id: 'spi', label: 'SPI (Elechouse ST25)' },
  { id: 'pn532', label: 'PN532 SPI' },
];

export function Nfc() {
  const [probing, setProbing] = useState(true);
  const [detected, setDetected] = useState(false);
  const [bus, setBus] = useState('i2c');
  const [backend, setBackend] = useState('');
  const [busy, setBusy] = useState(false);

  function applyStatus(st) {
    if (!st) return;
    if (typeof st.detected === 'boolean') setDetected(!!st.detected);
    if (st.bus) setBus(st.bus);
    if (typeof st.backend === 'string') setBackend(st.backend);
    if (st.probed) setProbing(false);
  }

  async function refreshStatus() {
    for (let i = 0; i < 12; i++) {
      const st = await api.nfcStatus();
      if (st?.ok) {
        applyStatus(st);
        if (st.probed && st.bus) return;
      }
      await sleep(150);
    }
  }

  async function probe() {
    setProbing(true);
    try {
      const done = waitForNfc(['nfc_init_done'], 8000).catch(() => null);
      const res = await api.nfcInit();
      if (!res?.ok) {
        showToast(res?.error || 'NFC busy', 'error');
        setProbing(false);
        return;
      }
      await done;
      await refreshStatus();
    } catch (e) {
      showToast('NFC probe failed', 'error');
    } finally {
      setProbing(false);
    }
  }

  useEffect(() => {
    probe();
  }, []);

  useEffect(() => wsAddListener((msg) => {
    if (msg.type === 'nfc_init_done') {
      applyStatus(msg);
      setProbing(false);
    } else if (msg.type === 'nfc_bus_set' && msg.bus) {
      setBus(msg.bus);
    }
  }), []);

  async function changeBus(mode) {
    if (!mode || mode === bus || busy || probing) return;
    setBusy(true);
    try {
      const done = waitForNfc(['nfc_init_done'], 8000).catch(() => null);
      const res = await api.nfcSetBus(mode);
      if (!res?.ok) {
        showToast(res?.error || 'Bus change failed', 'error');
        return;
      }
      setBus(mode);
      setProbing(true);
      await done;
      await refreshStatus();
    } finally {
      setBusy(false);
      setProbing(false);
    }
  }

  const statusLabel = probing ? 'Probing…' : (detected ? 'NFC ready' : 'NFC not detected');
  const statusClass = probing ? '' : (detected ? 'ok' : 'warn');

  return (
    <Layout title="NFC" back="/">
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Hardware</h3>
          <span class={`badge ${statusClass}`}>{statusLabel}</span>
        </div>
        <div class="kv">
          <div class="kv-row">
            <span class="kv-key">Bus</span>
            <span class="kv-val">{bus || '—'}</span>
          </div>
          {backend ? (
            <div class="kv-row">
              <span class="kv-key">Backend</span>
              <span class="kv-val">{backend}</span>
            </div>
          ) : null}
        </div>
        <div class="field">
          <label class="field-label">Transport</label>
          <select
            class="select"
            value={bus}
            disabled={probing || busy}
            onChange={(e) => changeBus(e.currentTarget.value)}
          >
            {BUSES.map((b) => (
              <option key={b.id} value={b.id}>{b.label}</option>
            ))}
          </select>
        </div>
        <button class="btn btn-soft" onClick={probe} disabled={probing || busy}>
          {probing ? <span class="spinner" /> : null}
          {probing ? 'Probing...' : 'Re-probe'}
        </button>
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Modules</h3>
        </div>
        <div class="quick-grid">
          {TILES.map((tile) => {
            const locked = tile.id === 'read' && !detected;
            return (
              <button
                key={tile.id}
                class="action-card action-card-text-only action-accent-cyan"
                disabled={locked || probing}
                onClick={() => route(tile.path)}
              >
                <span class="action-title">{tile.title}</span>
                <span class="action-note">
                  {locked ? 'Module not detected' : tile.note}
                </span>
              </button>
            );
          })}
        </div>
      </section>
    </Layout>
  );
}
