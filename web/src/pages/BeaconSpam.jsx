import { useEffect, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { api } from '../api';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';

const MAX_SSIDS = 32;

export function BeaconSpam() {
  const [running, setRunning] = useState(false);
  const [ssids, setSsids] = useState(['Free WiFi', 'Starbucks', 'Airport']);
  const [draft, setDraft] = useState('');

  useEffect(() => wsAddListener((msg) => {
    if (msg.type === 'attack_started' && msg.attack === 'beacon_spam') setRunning(true);
    if (msg.type === 'attack_stopped') setRunning(false);
  }), []);

  function addSsid() {
    const trimmed = draft.trim();
    if (!trimmed) return;
    if (trimmed.length > 32) {
      showToast('SSID must be 1-32 characters', 'warning');
      return;
    }
    if (ssids.length >= MAX_SSIDS) {
      showToast(`Max ${MAX_SSIDS} SSIDs`, 'warning');
      return;
    }
    if (ssids.includes(trimmed)) {
      showToast('SSID already in list', 'warning');
      return;
    }
    setSsids((prev) => [...prev, trimmed]);
    setDraft('');
  }

  function removeSsid(idx) {
    setSsids((prev) => prev.filter((_, i) => i !== idx));
  }

  async function start() {
    const list = ssids.map((s) => s.trim()).filter(Boolean);
    if (!list.length) {
      showToast('Add at least one SSID', 'warning');
      return;
    }
    const res = await api.beaconSpam(list);
    if (res.ok) {
      setRunning(true);
      showToast(`Beacon spam started (${list.length} SSIDs)`, 'success');
    } else {
      showToast(res.error || 'Failed to start beacon spam', 'error');
    }
  }

  async function stop() {
    await api.stop();
    setRunning(false);
    showToast('Beacon spam stopped', 'warning');
  }

  return (
    <Layout
      title="Beacon Spam"
      subtitle="Broadcast fake beacon frames for the SSIDs below across the 2.4GHz band."
      back="/global"
    >
      <section class="glass-card card-body reveal">
        {!running ? (
          <>
            <div class="field">
              <label class="field-label">Add SSID</label>
              <div class="btn-row" style="margin-top:0">
                <input
                  class="input"
                  type="text"
                  maxLength={32}
                  value={draft}
                  onInput={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') addSsid(); }}
                  placeholder="Free WiFi"
                />
                <button class="btn btn-secondary" onClick={addSsid}>Add</button>
              </div>
            </div>

            <div class="section-head">
              <h3 class="section-title">SSID List</h3>
              <span class="badge">{ssids.length}/{MAX_SSIDS}</span>
            </div>
            {ssids.length > 0 ? (
              <ul class="observer-clients">
                {ssids.map((s, idx) => (
                  <li class="observer-client" key={`${s}-${idx}`} style="display:flex;justify-content:space-between;align-items:center">
                    <span>{s}</span>
                    <button class="soft-btn" onClick={() => removeSsid(idx)}>Remove</button>
                  </li>
                ))}
              </ul>
            ) : (
              <div class="empty-state">No SSIDs yet. Add some above.</div>
            )}
          </>
        ) : (
          <div class="kv">
            <div class="kv-row">
              <span class="kv-key">Broadcasting</span>
              <span class="kv-val">{ssids.length} SSIDs</span>
            </div>
          </div>
        )}

        <div class="btn-row">
          {!running ? (
            <button class="btn btn-primary" onClick={start} disabled={!ssids.length}>
              Start Beacon Spam
            </button>
          ) : (
            <button class="btn btn-danger" onClick={stop}>
              Stop Beacon Spam
            </button>
          )}
        </div>
      </section>
    </Layout>
  );
}
