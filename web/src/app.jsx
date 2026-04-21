import Router from 'preact-router';
import { useState, useEffect } from 'preact/hooks';
import { wsConnect, wsAddListener, wsIsConnected } from './ws';
import { getState, setState, subscribe } from './store';
import { ToastContainer } from './components/Toast';
import { Home } from './pages/Home';
import { Scan } from './pages/Scan';
import { Deauth } from './pages/Deauth';
import { EvilTwin } from './pages/EvilTwin';
import { RogueAP } from './pages/RogueAP';
import { SaeOverflow } from './pages/SaeOverflow';
import { Handshaker } from './pages/Handshaker';
import { Sniffer } from './pages/Sniffer';

export function App() {
  const [, forceUpdate] = useState(0);

  useEffect(() => {
    wsConnect();

    const removeWs = wsAddListener((msg) => {
      if (msg.type === 'ws_connected') setState({ wsConnected: true });
      if (msg.type === 'ws_disconnected') setState({ wsConnected: false });

      if (msg.type === 'scan_network') {
        const st = getState();
        const exists = st.networks.find(n => n.index === msg.network.index);
        if (!exists) {
          setState({ networks: [...st.networks, msg.network] });
        }
      }
      if (msg.type === 'scan_complete') {
        setState({ status: 'idle' });
      }
      if (msg.type === 'attack_started') {
        setState({ status: msg.attack });
      }
      if (msg.type === 'attack_stopped') {
        setState({ status: 'idle' });
      }
    });

    const removeSub = subscribe(() => forceUpdate(n => n + 1));

    return () => {
      removeWs();
      removeSub();
    };
  }, []);

  const st = getState();

  return (
    <div>
      <div class="header">
        <h1>JanOS</h1>
        <div class="status-bar" style="margin:0;padding:6px 10px;border:none;background:transparent">
          <div class={`status-dot ${st.wsConnected ? (st.status !== 'idle' ? 'busy' : 'active') : ''}`} />
          <span class="status-text">
            {!st.wsConnected ? 'Connecting...' : st.status === 'idle' ? 'Ready' : st.status}
          </span>
        </div>
      </div>

      <Router>
        <Home path="/" />
        <Scan path="/scan" />
        <Deauth path="/deauth" />
        <EvilTwin path="/eviltwin" />
        <RogueAP path="/rogueap" />
        <SaeOverflow path="/sae" />
        <Handshaker path="/handshaker" />
        <Sniffer path="/sniffer" />
      </Router>

      <ToastContainer />
    </div>
  );
}
