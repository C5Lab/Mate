import { useEffect, useState } from 'preact/hooks';
import { Layout } from '../../components/Layout';
import { api } from '../../api';
import { showToast } from '../../components/Toast';
import { wsAddListener } from '../../ws';

export function SubGhzTransmit() {
  const [signals, setSignals] = useState([]);
  const [loading, setLoading] = useState(false);
  const [confirm, setConfirm] = useState(null);
  const [status, setStatus] = useState('Idle');

  async function load() {
    setLoading(true);
    try {
      const cached = await api.subghzList();
      if (cached.ok) {
        setSignals(cached.signals || []);
      } else {
        showToast(cached.error || 'list fetch failed', 'error');
      }
      await api.subghzListRefresh();
    } catch (e) {
      showToast('Failed to load signals', 'error');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  useEffect(() => wsAddListener((msg) => {
    if (msg.type === 'subghz_list_end') {
      api.subghzList().then((res) => {
        if (res.ok) setSignals(res.signals || []);
      });
    } else if (msg.type === 'subghz_tx_done') {
      setStatus(`Transmitted #${msg.idx}`);
      showToast(`TX done #${msg.idx}`, 'success');
    }
  }), []);

  async function transmit(idx) {
    setConfirm(null);
    const res = await api.subghzTx(idx);
    if (res.ok) {
      setStatus(`Sending #${idx}...`);
    } else {
      showToast(res.error || 'TX failed', 'error');
    }
  }

  return (
    <Layout title="SubGHZ Transmit" back="/subghz">
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Stored Signals</h3>
          <button class="btn btn-soft" onClick={load} disabled={loading}>
            {loading ? <span class="spinner" /> : null}
            {loading ? 'Loading...' : 'Refresh'}
          </button>
        </div>

        <div class="kv">
          <div class="kv-row">
            <span class="kv-key">Status</span>
            <span class="kv-val">{status}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">Count</span>
            <span class="kv-val">{signals.length}</span>
          </div>
        </div>

        {signals.length ? (
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
                      <button
                        class="btn btn-primary"
                        onClick={() => setConfirm(s)}
                      >
                        TX
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div class="empty-state">
            {loading ? 'Loading stored signals...' : 'No stored signals.'}
          </div>
        )}
      </section>

      {confirm ? (
        <div class="settings-overlay" onClick={() => setConfirm(null)}>
          <section class="glass-card settings-panel" onClick={(e) => e.stopPropagation()}>
            <div class="section-head">
              <h3 class="section-title">Confirm Transmit</h3>
            </div>
            <div class="kv">
              <div class="kv-row">
                <span class="kv-key">Index</span>
                <span class="kv-val">#{confirm.idx}</span>
              </div>
              <div class="kv-row">
                <span class="kv-key">Type</span>
                <span class="kv-val">{confirm.type || confirm.signalType || '-'}</span>
              </div>
              <div class="kv-row">
                <span class="kv-key">Frequency</span>
                <span class="kv-val">{Number(confirm.freq).toFixed(2)} MHz</span>
              </div>
            </div>
            <div class="btn-row">
              <button class="btn btn-soft" onClick={() => setConfirm(null)}>Cancel</button>
              <button class="btn btn-primary" onClick={() => transmit(confirm.idx)}>Transmit</button>
            </div>
          </section>
        </div>
      ) : null}
    </Layout>
  );
}
