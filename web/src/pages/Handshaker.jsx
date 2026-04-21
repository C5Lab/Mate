import { useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { AttackMonitor } from '../components/AttackMonitor';
import { api } from '../api';
import { getState } from '../store';
import { showToast } from '../components/Toast';

export function Handshaker() {
  const [running, setRunning] = useState(false);
  const [captures, setCaptures] = useState([]);
  const st = getState();

  async function start() {
    if (st.selected.size > 0) {
      await api.select(Array.from(st.selected));
    }
    const res = await api.handshake();
    if (res.ok) {
      setRunning(true);
    } else {
      showToast(res.error || 'Failed', 'error');
    }
  }

  async function stop() {
    await api.stop();
    setRunning(false);
  }

  function onEvent(msg) {
    if (msg.type === 'attack_stopped') setRunning(false);
    if (msg.type === 'handshake_captured' || msg.type === 'handshake_saved') {
      setCaptures(prev => [...prev, {
        ssid: msg.ssid || 'unknown',
        file: msg.file || '',
        ts: new Date().toLocaleTimeString(),
      }]);
      showToast('Handshake captured!', 'success');
    }
    if (msg.type === 'pcap_saved') {
      setCaptures(prev => [...prev, {
        ssid: '',
        file: msg.file,
        ts: new Date().toLocaleTimeString(),
      }]);
    }
  }

  return (
    <Layout title="Handshake Capture" back="/">
      <div style="margin-bottom:12px;font-size:13px;color:var(--muted)">
        {st.selected.size > 0
          ? `Targeting ${st.selected.size} network(s)`
          : 'No selection — will scan all and attack automatically'}
      </div>

      <div class="btn-row" style="margin-top:0;margin-bottom:14px">
        {!running ? (
          <button class="btn btn-green" onClick={start}>
            {'\u{1F91D}'} Start Handshaker
          </button>
        ) : (
          <button class="btn btn-red" onClick={stop}>
            {'\u{26D4}'} Stop
          </button>
        )}
      </div>

      {captures.length > 0 && (
        <div class="panel">
          <div class="panel-header">
            Captures ({captures.length})
            <span class="badge badge-green">{'\u{2705}'}</span>
          </div>
          <div class="panel-body" style="padding:8px 14px">
            {captures.map((c, i) => (
              <div key={i} style="font-size:12px;padding:4px 0;border-bottom:1px solid #1a2a3a">
                <span style="color:var(--green);font-weight:600">{c.ssid || 'PCAP'}</span>
                <span style="color:var(--muted);margin-left:8px">{c.ts}</span>
                {c.file && <div style="font-size:11px;color:var(--muted);margin-top:2px">{c.file}</div>}
              </div>
            ))}
          </div>
        </div>
      )}

      <AttackMonitor title="Handshaker Monitor" attackType="handshake" onEvent={onEvent} />
    </Layout>
  );
}
