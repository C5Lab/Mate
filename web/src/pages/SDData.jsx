import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { api } from '../api';
import { wsAddListener } from '../ws';

function DataSection({ title, rows, emptyLabel }) {
  return (
    <section class="glass-card card-body reveal">
      <div class="section-head">
        <h3 class="section-title">{title}</h3>
        <div class="row-actions">
          <span class="badge info">{rows.length}</span>
        </div>
      </div>

      {!rows.length ? (
        <div class="empty-state">{emptyLabel}</div>
      ) : (
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>Item</th>
                <th>Meta</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id}>
                  <td>{row.item}</td>
                  <td>{row.meta}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

const MAX_RETRIES = 12;
// Per-loader base delays are staggered so the four loaders don't keep hitting
// the C5's single-command FSM at the exact same instant and starving each other.
const RETRY_MS = {
  evil: 1200,
  portal: 1500,
  handshakes: 1800,
  wardrive: 2100,
};

export function SDData() {
  const [evilTwinPasswords, setEvilTwinPasswords] = useState([]);
  const [portalPasswords, setPortalPasswords] = useState([]);
  const [handshakes, setHandshakes] = useState([]);
  const [wardriveLogs, setWardriveLogs] = useState([]);

  // name -> { timer, count } for the "still loading, poll again" pattern.
  const retryRefs = useRef({});

  useEffect(() => {
    loadEvilPasswords();
    loadPortalPasswords();
    loadHandshakes();
    loadWardriveLogs();

    const remove = wsAddListener((msg) => {
      if (msg.type === 'password_received') {
        setEvilTwinPasswords((prev) => [
          {
            id: `et-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
            item: msg.ssid || 'Evil Twin',
            meta: msg.password,
          },
          ...prev,
        ]);
      }

      if (msg.type === 'handshake_captured' || msg.type === 'handshake_saved' || msg.type === 'pcap_saved') {
        setHandshakes((prev) => [
          {
            id: `hs-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
            item: msg.ssid || 'Handshake',
            meta: msg.file || new Date().toLocaleTimeString(),
          },
          ...prev,
        ]);
      }
    });

    return () => {
      Object.values(retryRefs.current).forEach((r) => {
        if (r && r.timer) clearTimeout(r.timer);
      });
      retryRefs.current = {};
      remove();
    };
  }, []);

  function retryLater(name, fn) {
    const r = retryRefs.current[name] || (retryRefs.current[name] = { timer: null, count: 0 });
    if (r.timer) return;
    r.count += 1;
    if (r.count > MAX_RETRIES) return;
    r.timer = setTimeout(() => {
      r.timer = null;
      fn();
    }, RETRY_MS[name] || 1500);
  }

  function resetRetry(name) {
    const r = retryRefs.current[name];
    if (r) {
      if (r.timer) clearTimeout(r.timer);
      retryRefs.current[name] = { timer: null, count: 0 };
    }
  }

  function mapPasswords(list, prefix) {
    return list.map((entry, idx) => ({
      id: `${prefix}-${idx}-${entry.ssid}`,
      item: `${entry.ssid}`,
      meta: entry.password,
    }));
  }

  // A password reply is "ready" only when it carries a list AND is not still
  // loading (the loading response ships an empty passwords array too).
  async function loadEvilPasswords() {
    try {
      const data = await api.passwords('evil');
      if (data.passwords && data.status !== 'loading') {
        resetRetry('evil');
        setEvilTwinPasswords(mapPasswords(data.passwords, 'evil'));
        return;
      }
    } catch (e) {
      /* fall through to retry */
    }
    retryLater('evil', loadEvilPasswords);
  }

  async function loadPortalPasswords() {
    try {
      const data = await api.passwords('portal');
      if (data.passwords && data.status !== 'loading') {
        resetRetry('portal');
        setPortalPasswords(mapPasswords(data.passwords, 'portal'));
        return;
      }
    } catch (e) {
      /* fall through to retry */
    }
    retryLater('portal', loadPortalPasswords);
  }

  async function loadHandshakes() {
    try {
      const data = await api.handshakes();
      if (data.files) {
        resetRetry('handshakes');
        setHandshakes(
          data.files.map((f) => ({
            id: `hs-file-${f.index}-${f.name}`,
            item: f.name,
            meta: `#${f.index} /sdcard/lab/handshakes`,
          })),
        );
        return;
      }
    } catch (e) {
      /* fall through to retry */
    }
    retryLater('handshakes', loadHandshakes);
  }

  async function loadWardriveLogs() {
    try {
      const data = await api.wardriveLogs();
      if (data.files) {
        resetRetry('wardrive');
        setWardriveLogs(
          data.files.map((f) => ({
            id: `wardrive-${f.index}-${f.name}`,
            item: f.name,
            meta: `#${f.index} /sdcard/lab/wardrives`,
          })),
        );
        return;
      }
    } catch (e) {
      /* fall through to retry */
    }
    retryLater('wardrive', loadWardriveLogs);
  }

  function reloadAll() {
    ['evil', 'portal', 'handshakes', 'wardrive'].forEach(resetRetry);
    loadEvilPasswords();
    loadPortalPasswords();
    loadHandshakes();
    loadWardriveLogs();
  }

  return (
    <Layout
      title="Data"
      back="/"
      actions={
        <button class="btn btn-secondary" onClick={reloadAll}>
          Refresh
        </button>
      }
    >
      <DataSection
        title="Evil Twin Passwords"
        rows={evilTwinPasswords}
        emptyLabel="No Evil Twin credentials found."
      />

      <DataSection
        title="Portal Passwords"
        rows={portalPasswords}
        emptyLabel="No portal passwords found."
      />

      <DataSection
        title="Handshakes"
        rows={handshakes}
        emptyLabel="No handshake captures found."
      />

      <DataSection
        title="Wardrive Logs"
        rows={wardriveLogs}
        emptyLabel="No wardrive log files found."
      />
    </Layout>
  );
}
