import { useEffect, useRef, useState } from 'preact/hooks';
import { wsAddListener } from '../ws';

export function AttackMonitor({ title, attackType, onEvent }) {
  const [lines, setLines] = useState([]);
  const [running, setRunning] = useState(false);
  const logRef = useRef(null);

  useEffect(() => {
    const remove = wsAddListener((msg) => {
      if (msg.type === 'attack_started' && (!attackType || msg.attack === attackType)) {
        setRunning(true);
        addLine('line-info', `${msg.attack || attackType || 'operation'} started`);
      }

      if (msg.type === 'attack_stopped') {
        setRunning(false);
        addLine('line-info', 'Operation stopped');
      }

      if (msg.type === 'uart_line') {
        addLine('', msg.data);
      }

      if (msg.type === 'client_connected') addLine('line-event', `Client linked: ${msg.mac}`);
      if (msg.type === 'password_received') addLine('line-event', `Credential captured: ${msg.password}`);
      if (msg.type === 'password_verified') addLine('line-event', 'Credential verified');
      if (msg.type === 'handshake_captured') addLine('line-event', 'Handshake captured');
      if (msg.type === 'pcap_saved') addLine('line-event', `PCAP saved: ${msg.file}`);
      if (msg.type === 'handshake_saved') addLine('line-event', `Handshake file: ${msg.ssid || 'unknown'}`);
      if (msg.type === 'sniffer_count') addLine('line-info', `Packets: ${msg.count}`);

      if (onEvent) onEvent(msg);
    });

    return remove;
  }, [attackType]);

  function addLine(cls, text) {
    setLines((prev) => {
      const next = [...prev, { cls, text, ts: new Date().toLocaleTimeString() }];
      return next.slice(-120);
    });

    setTimeout(() => {
      if (logRef.current) {
        logRef.current.scrollTop = logRef.current.scrollHeight;
      }
    }, 20);
  }

  return (
    <section class="log-card reveal">
      <header class="log-head">
        <span class="log-title">{title || 'Live Monitor'}</span>
        <span class={`badge ${running ? 'ok' : ''}`}>
          {running ? <span class="spinner" /> : null}
          {running ? 'Live' : 'Idle'}
        </span>
      </header>
      <div class="log-stream" ref={logRef}>
        {lines.length === 0 ? <div class="log-empty">Waiting for telemetry...</div> : null}
        {lines.map((line, index) => (
          <div key={index} class={`log-line ${line.cls}`}>
            <span class="log-time">{line.ts}</span>
            {line.text}
          </div>
        ))}
      </div>
    </section>
  );
}
