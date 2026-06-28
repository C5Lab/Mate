import { useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { showToast } from '../components/Toast';

export function Bluetooth() {
  const [airtagRunning, setAirtagRunning] = useState(false);
  const [deviceRunning, setDeviceRunning] = useState(false);
  const [airtagResults, setAirtagResults] = useState([]);
  const [deviceResults, setDeviceResults] = useState([]);

  const unsupportedMsg = 'Bluetooth commands are not exposed by current firmware API.';

  function runUnsupported(setRunning, listSetter, label) {
    setRunning(true);
    setTimeout(() => {
      setRunning(false);
      listSetter((prev) => [
        {
          id: `${label}-${Date.now()}`,
          item: `${label} request sent`,
          meta: 'Awaiting firmware support',
        },
        ...prev,
      ]);
      showToast(unsupportedMsg, 'warning');
    }, 900);
  }

  return (
    <Layout
      title="Bluetooth"
      subtitle="Dedicated controls for AirTag scanning and nearby Bluetooth device discovery."
      back="/"
    >
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">AirTag Scan</h3>
          <span class="badge warn">Preview</span>
        </div>
        <div class="btn-row">
          <button class="btn btn-info" onClick={() => runUnsupported(setAirtagRunning, setAirtagResults, 'AirTag')}>
            {airtagRunning ? <span class="spinner" /> : null}
            {airtagRunning ? 'Scanning...' : 'Start AirTag Scan'}
          </button>
        </div>
        {airtagResults.length ? (
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>Result</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {airtagResults.map((row) => (
                  <tr key={row.id}>
                    <td>{row.item}</td>
                    <td>{row.meta}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div class="empty-state">No AirTag scan output yet.</div>
        )}
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Device Scan</h3>
          <span class="badge warn">Preview</span>
        </div>
        <div class="btn-row">
          <button class="btn btn-success" onClick={() => runUnsupported(setDeviceRunning, setDeviceResults, 'Device')}>
            {deviceRunning ? <span class="spinner" /> : null}
            {deviceRunning ? 'Scanning...' : 'Start Device Scan'}
          </button>
        </div>
        {deviceResults.length ? (
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>Result</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {deviceResults.map((row) => (
                  <tr key={row.id}>
                    <td>{row.item}</td>
                    <td>{row.meta}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div class="empty-state">No Bluetooth device data yet.</div>
        )}
      </section>
    </Layout>
  );
}
