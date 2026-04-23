import { useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { AttackMonitor } from '../components/AttackMonitor';
import { PortalPicker } from '../components/PortalPicker';
import { api } from '../api';
import { showToast } from '../components/Toast';

export function Portal() {
  const [running, setRunning] = useState(false);
  const [ssid, setSsid] = useState('');
  const [portalSelected, setPortalSelected] = useState(false);

  async function start() {
    const trimmed = ssid.trim();
    if (!trimmed) {
      showToast('SSID is required', 'warning');
      return;
    }
    if (!portalSelected) {
      showToast('Select a portal template', 'warning');
      return;
    }

    const res = await api.portal(trimmed);
    if (res.ok) {
      setRunning(true);
      showToast('Portal started', 'success');
    } else {
      showToast(res.error || 'Failed to start portal', 'error');
    }
  }

  async function stop() {
    await api.stop();
    setRunning(false);
    showToast('Stopped', 'warning');
  }

  return (
    <Layout
      title="Portal"
      subtitle="Open captive portal with your own SSID and selected HTML template."
      back="/global"
    >
      <section class="glass-card card-body reveal">
        {!running ? (
          <>
            <div class="field">
              <label class="field-label">Portal SSID</label>
              <input
                class="input"
                type="text"
                maxLength={32}
                value={ssid}
                onInput={(e) => setSsid(e.target.value)}
                placeholder="FreeWiFi"
              />
            </div>

            <PortalPicker onSelect={(idx) => setPortalSelected(idx > 0)} />
          </>
        ) : null}

        <div class="btn-row">
          {!running ? (
            <button class="btn btn-primary" onClick={start} disabled={!portalSelected || !ssid.trim()}>
              Start Portal
            </button>
          ) : (
            <button class="btn btn-danger" onClick={stop}>
              Stop Portal
            </button>
          )}
        </div>
      </section>

      <AttackMonitor
        title="Portal Telemetry"
        attackType="portal"
        onEvent={(msg) => {
          if (msg.type === 'attack_stopped') setRunning(false);
        }}
      />
    </Layout>
  );
}
