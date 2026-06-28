import { useEffect, useState } from 'preact/hooks';
import { Layout } from '../../components/Layout';
import { api } from '../../api';
import { showToast } from '../../components/Toast';
import { wsAddListener } from '../../ws';

export function SubGhzManage() {
  const [signals, setSignals] = useState([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(null);
  const [importCount, setImportCount] = useState(0);
  const [confirmClear, setConfirmClear] = useState(false);

  async function refresh() {
    setLoading(true);
    try {
      const cached = await api.subghzList();
      if (cached.ok) setSignals(cached.signals || []);
      await api.subghzListRefresh();
    } catch (e) {
      showToast('Failed to load signals', 'error');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  useEffect(() => wsAddListener((msg) => {
    if (msg.type === 'subghz_list_end') {
      api.subghzList().then((res) => {
        if (res.ok) setSignals(res.signals || []);
      });
      setBusy(null);
    } else if (msg.type === 'subghz_import_progress') {
      setImportCount(msg.count || 0);
    } else if (msg.type === 'subghz_import_done') {
      const count = msg.count || 0;
      if (msg.error === 'sd_missing') {
        showToast('Import failed: SD card / lab/subghz dir missing', 'error');
      } else {
        showToast(`Imported ${count} signal(s)`, 'success');
      }
      setBusy(null);
      setImportCount(0);
      /* Backend also auto-refreshes, but trigger from here too as a safety
       * net so the table never gets stuck on the old contents. */
      api.subghzListRefresh().catch(() => {});
    } else if (msg.type === 'subghz_export_done') {
      showToast('Export complete', 'success');
      setBusy(null);
    }
  }), []);

  async function deleteSignal(idx) {
    const res = await api.subghzDelete(idx);
    if (res.ok) {
      showToast(`Deleted #${idx}`, 'success');
      setBusy('list');
      await api.subghzListRefresh();
    } else {
      showToast(res.error || 'Delete failed', 'error');
    }
  }

  async function clearAll() {
    setConfirmClear(false);
    const res = await api.subghzClear();
    if (res.ok) {
      showToast('All signals cleared', 'success');
      setSignals([]);
      setBusy('list');
      await api.subghzListRefresh();
    } else {
      showToast(res.error || 'Clear failed', 'error');
    }
  }

  async function doExport() {
    setBusy('export');
    const res = await api.subghzExport();
    if (!res.ok) {
      showToast(res.error || 'Export failed', 'error');
      setBusy(null);
    }
  }

  async function doImport() {
    setBusy('import');
    setImportCount(0);
    const res = await api.subghzImport();
    if (!res.ok) {
      showToast(res.error || 'Import failed', 'error');
      setBusy(null);
    }
  }

  return (
    <Layout title="SubGHZ Manage" back="/subghz">
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">SD Storage</h3>
        </div>
        <div class="btn-row">
          <button class="btn btn-info" onClick={doExport} disabled={busy === 'export'}>
            {busy === 'export' ? <span class="spinner" /> : null}
            {busy === 'export' ? 'Exporting...' : 'Export All to SD'}
          </button>
          <button class="btn btn-success" onClick={doImport} disabled={busy === 'import'}>
            {busy === 'import' ? <span class="spinner" /> : null}
            {busy === 'import'
              ? `Importing... (${importCount})`
              : 'Import All from SD'}
          </button>
        </div>
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Stored Signals</h3>
          <button class="btn btn-soft" onClick={refresh} disabled={loading}>
            {loading ? <span class="spinner" /> : null}
            {loading ? 'Loading...' : 'Refresh'}
          </button>
        </div>

        <div class="kv">
          <div class="kv-row">
            <span class="kv-key">Count</span>
            <span class="kv-val">{signals.length}</span>
          </div>
        </div>

        {signals.length ? (
          <>
            <div class="table-wrap">
              <table class="table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Type</th>
                    <th>MHz</th>
                    <th>Serial</th>
                    <th>Btn</th>
                    <th>Cnt</th>
                    <th>Mf</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {signals.map((s) => (
                    <tr key={s.idx}>
                      <td>{s.idx}</td>
                      <td>{s.type || s.signalType || '-'}</td>
                      <td>{Number(s.freq).toFixed(2)}</td>
                      <td>{s.serial || s.id || '-'}</td>
                      <td>{s.btn ?? '-'}</td>
                      <td>{s.cnt ?? '-'}</td>
                      <td>{s.mf || (s.bits ? `${s.bits}b` : '-')}</td>
                      <td>
                        <button class="btn btn-danger" onClick={() => deleteSignal(s.idx)}>Del</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <button class="btn btn-danger btn-block" onClick={() => setConfirmClear(true)}>
              Clear All Signals
            </button>
          </>
        ) : (
          <div class="empty-state">
            {loading ? 'Loading stored signals...' : 'No stored signals.'}
          </div>
        )}
      </section>

      {confirmClear ? (
        <div class="settings-overlay" onClick={() => setConfirmClear(false)}>
          <section class="glass-card settings-panel" onClick={(e) => e.stopPropagation()}>
            <div class="section-head">
              <h3 class="section-title">Clear All Signals?</h3>
            </div>
            <p>This will permanently remove all captured signals from device memory.</p>
            <div class="btn-row">
              <button class="btn btn-soft" onClick={() => setConfirmClear(false)}>Cancel</button>
              <button class="btn btn-danger" onClick={clearAll}>Clear All</button>
            </div>
          </section>
        </div>
      ) : null}
    </Layout>
  );
}
