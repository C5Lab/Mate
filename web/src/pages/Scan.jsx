import { route } from 'preact-router';
import { Layout } from '../components/Layout';
import { NetworkList } from '../components/NetworkList';
import { api } from '../api';
import { getState, setState, toggleNetwork, setAllNetworks } from '../store';
import { showToast } from '../components/Toast';

let pollTimer = null;
let pollTimeout = null;

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  if (pollTimeout) { clearTimeout(pollTimeout); pollTimeout = null; }
}

export function Scan() {
  const st = getState();
  const scanning = st.status === 'scanning' || st.status === 'scan';

  async function doScan() {
    stopPolling();
    setState({ networks: [], selected: new Set(), status: 'scanning' });
    try {
      await api.scan();
    } catch (e) {
      showToast('Scan failed', 'error');
      setState({ status: 'idle' });
      return;
    }

    pollTimer = setInterval(async () => {
      try {
        const data = await api.scanResults();
        if (data && data.complete) {
          stopPolling();
          setState({ networks: data.networks, status: 'idle' });
          showToast(`Found ${data.networks.length} networks`, 'success');
        }
      } catch (e) {
        /* fetch failed, keep polling */
      }
    }, 2000);

    pollTimeout = setTimeout(() => {
      stopPolling();
      const cur = getState().status;
      if (cur === 'scanning' || cur === 'scan') {
        setState({ status: 'idle' });
        showToast('Scan timed out', 'warning');
      }
    }, 60000);
  }

  async function doSelect() {
    const indices = Array.from(st.selected);
    if (indices.length === 0) {
      showToast('Select at least one network', 'warning');
      return;
    }
    try {
      await api.select(indices);
      showToast(`${indices.length} network(s) selected`, 'success');
      route('/');
    } catch (e) {
      showToast('Select failed, retrying...', 'error');
      setTimeout(() => doSelect(), 1000);
    }
  }

  return (
    <Layout title="WiFi Scan" back="/">
      <div class="btn-row" style="margin-top:0;margin-bottom:14px">
        <button class="btn btn-cyan" onClick={doScan} disabled={scanning}>
          {scanning ? <><span class="spinner" /> Scanning...</> : '\u{1F4E1} Start Scan'}
        </button>
        {st.selected.size > 0 && !scanning && (
          <button class="btn btn-magenta" onClick={doSelect}>
            Select {st.selected.size} &rarr;
          </button>
        )}
      </div>

      <NetworkList
        networks={st.networks}
        selected={st.selected}
        onToggle={toggleNetwork}
        onToggleAll={setAllNetworks}
      />
    </Layout>
  );
}
