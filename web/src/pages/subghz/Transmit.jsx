import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../../components/Layout';
import { api } from '../../api';
import { showToast } from '../../components/Toast';
import { wsAddListener } from '../../ws';
import { fetchSubghzListAfterRefresh } from '../../subghzUtil';

// If the WS `subghz_tx_done` confirmation is lost, resolve the "Sending..."
// status after this long so the UI never gets stuck. A replay is a short
// burst, so a few seconds is plenty.
const TX_CONFIRM_TIMEOUT_MS = 4000;

export function SubGhzTransmit() {
  const [signals, setSignals] = useState([]);
  const [loading, setLoading] = useState(false);
  const [confirm, setConfirm] = useState(null);
  const [status, setStatus] = useState('Idle');

  // Track the in-flight TX so the WS confirmation and the timeout fallback
  // don't race, and so a stale confirmation can't clobber a newer send.
  const pendingTxRef = useRef(null);
  const txTimerRef = useRef(null);

  async function load() {
    setLoading(true);
    try {
      const res = await fetchSubghzListAfterRefresh('sd');
      if (res.ok) {
        setSignals(res.signals || []);
      } else {
        showToast(res.error || 'list fetch failed', 'error');
      }
    } catch (e) {
      showToast('Failed to load signals', 'error');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    const removeWs = wsAddListener((msg) => {
      if (msg.type === 'subghz_list_end') {
        api.subghzList().then((res) => {
          if (res.ok) setSignals(res.signals || []);
        });
      } else if (msg.type === 'subghz_tx_done') {
        if (txTimerRef.current) {
          clearTimeout(txTimerRef.current);
          txTimerRef.current = null;
        }
        pendingTxRef.current = null;
        setStatus(`Transmitted #${msg.idx}`);
        showToast(`TX done #${msg.idx}`, 'success');
      }
    });
    return () => {
      removeWs();
      if (txTimerRef.current) clearTimeout(txTimerRef.current);
    };
  }, []);

  async function transmit(idx) {
    setConfirm(null);
    if (txTimerRef.current) {
      clearTimeout(txTimerRef.current);
      txTimerRef.current = null;
    }
    const res = await api.subghzTx(idx, 'sd');
    if (!res.ok) {
      pendingTxRef.current = null;
      showToast(res.error || 'TX failed', 'error');
      return;
    }
    setStatus(`Sending #${idx}...`);
    pendingTxRef.current = idx;
    // Fallback: the command was accepted by the host; if the WS confirmation
    // never arrives, don't leave the UI stuck on "Sending...".
    txTimerRef.current = setTimeout(() => {
      if (pendingTxRef.current === idx) {
        pendingTxRef.current = null;
        txTimerRef.current = null;
        setStatus(`Sent #${idx}`);
      }
    }, TX_CONFIRM_TIMEOUT_MS);
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
