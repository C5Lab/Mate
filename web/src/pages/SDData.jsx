import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { api } from '../api';
import { wsAddListener } from '../ws';
import { showToast } from '../components/Toast';

function DataSection({ title, rows, emptyLabel, onDeleteOne, onDeleteAll }) {
  return (
    <section class="glass-card card-body reveal">
      <div class="section-head">
        <h3 class="section-title">{title}</h3>
        <div class="row-actions">
          <span class="badge info">{rows.length}</span>
          <button class="soft-btn" onClick={onDeleteAll} disabled={!rows.length}>
            Clear
          </button>
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
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id}>
                  <td>{row.item}</td>
                  <td>{row.meta}</td>
                  <td>
                    <button class="soft-btn" onClick={() => onDeleteOne(row.id)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export function SDData() {
  const [evilTwinPasswords, setEvilTwinPasswords] = useState([]);
  const [portalPasswords, setPortalPasswords] = useState([]);
  const [handshakes, setHandshakes] = useState([]);
  const [wardriveLogs, setWardriveLogs] = useState([]);

  const wardriveRetryRef = useRef(null);
  const wardriveRetryCountRef = useRef(0);

  useEffect(() => {
    loadPortalPasswords();
    loadWardriveLogs();

    const remove = wsAddListener((msg) => {
      if (msg.type === 'password_received') {
        setEvilTwinPasswords((prev) => [
          {
            id: `et-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
            item: msg.password,
            meta: `Captured ${new Date().toLocaleTimeString()}`,
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
      if (wardriveRetryRef.current) {
        clearTimeout(wardriveRetryRef.current);
        wardriveRetryRef.current = null;
      }
      wardriveRetryCountRef.current = 0;
      remove();
    };
  }, []);

  function scheduleWardriveRetry() {
    if (wardriveRetryRef.current) return;
    wardriveRetryRef.current = setTimeout(() => {
      wardriveRetryRef.current = null;
      loadWardriveLogs();
    }, 1400);
  }

  async function loadPortalPasswords() {
    try {
      const data = await api.passwords();
      if (data.passwords) {
        setPortalPasswords(
          data.passwords.map((entry, idx) => ({
            id: `portal-${idx}-${entry.ssid}`,
            item: `${entry.ssid}`,
            meta: entry.password,
          })),
        );
      }
    } catch (e) {
      showToast('Unable to load SD password data', 'warning');
    }
  }

  async function loadWardriveLogs() {
    try {
      const data = await api.wardriveLogs();
      if (data.files) {
        wardriveRetryCountRef.current = 0;
        setWardriveLogs(
          data.files.map((f) => ({
            id: `wardrive-${f.index}-${f.name}`,
            item: f.name,
            meta: `#${f.index} /sdcard/lab/wardrives`,
          })),
        );
        return;
      }
      if (data.status === 'loading') {
        wardriveRetryCountRef.current += 1;
        if (wardriveRetryCountRef.current <= 6) {
          scheduleWardriveRetry();
        } else {
          setWardriveLogs([]);
        }
      }
    } catch (e) {
      showToast('Unable to load wardrive logs', 'warning');
      wardriveRetryCountRef.current += 1;
      if (wardriveRetryCountRef.current <= 6) {
        scheduleWardriveRetry();
      }
    }
  }

  function deleteOne(setter, id) {
    setter((prev) => prev.filter((row) => row.id !== id));
  }

  function deleteAll(setter) {
    setter([]);
  }

  return (
    <Layout
      title="Data"
      back="/"
      actions={
        <button class="btn btn-secondary" onClick={() => { loadPortalPasswords(); loadWardriveLogs(); }}>
          Refresh
        </button>
      }
    >
      <DataSection
        title="Evil Twin Passwords"
        rows={evilTwinPasswords}
        emptyLabel="No Evil Twin credentials in this session."
        onDeleteOne={(id) => deleteOne(setEvilTwinPasswords, id)}
        onDeleteAll={() => deleteAll(setEvilTwinPasswords)}
      />

      <DataSection
        title="Portal Passwords"
        rows={portalPasswords}
        emptyLabel="No portal passwords loaded."
        onDeleteOne={(id) => deleteOne(setPortalPasswords, id)}
        onDeleteAll={() => deleteAll(setPortalPasswords)}
      />

      <DataSection
        title="Handshakes"
        rows={handshakes}
        emptyLabel="No handshake captures yet."
        onDeleteOne={(id) => deleteOne(setHandshakes, id)}
        onDeleteAll={() => deleteAll(setHandshakes)}
      />

      <DataSection
        title="Wardrive Logs"
        rows={wardriveLogs}
        emptyLabel="No wardrive log files found."
        onDeleteOne={(id) => deleteOne(setWardriveLogs, id)}
        onDeleteAll={() => deleteAll(setWardriveLogs)}
      />
    </Layout>
  );
}
