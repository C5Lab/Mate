import { useState, useEffect, useRef } from 'preact/hooks';
import { wsAddListener } from '../ws';

export function AttackMonitor({ title, attackType, onEvent }) {
  const [lines, setLines] = useState([]);
  const [running, setRunning] = useState(false);
  const logRef = useRef(null);

  useEffect(() => {
    const remove = wsAddListener((msg) => {
      if (msg.type === 'attack_started' && msg.attack === attackType) {
        setRunning(true);
        addLine('info', `${attackType} started`);
      }
      if (msg.type === 'attack_stopped') {
        setRunning(false);
        addLine('info', 'Stopped');
      }
      if (msg.type === 'uart_line') {
        addLine('', msg.data);
      }

      if (msg.type === 'client_connected') addLine('event', `Client: ${msg.mac}`);
      if (msg.type === 'password_received') addLine('event', `Password: ${msg.password}`);
      if (msg.type === 'password_verified') addLine('event', 'Password verified!');
      if (msg.type === 'handshake_captured') addLine('event', 'Handshake captured!');
      if (msg.type === 'pcap_saved') addLine('event', `PCAP: ${msg.file}`);
      if (msg.type === 'sniffer_count') addLine('info', `Packets: ${msg.count}`);
      if (msg.type === 'handshake_saved') addLine('event', `Saved for: ${msg.ssid}`);

      if (onEvent) onEvent(msg);
    });
    return remove;
  }, [attackType]);

  function addLine(cls, text) {
    setLines(prev => {
      const next = [...prev, { cls, text, ts: new Date().toLocaleTimeString() }];
      return next.slice(-100);
    });
    setTimeout(() => {
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, 50);
  }

  return (
    <div class="monitor">
      <div class="monitor-title">
        {title || 'Monitor'}
        {running && <span class="spinner" style="margin-left:8px" />}
      </div>
      <div class="monitor-log" ref={logRef}>
        {lines.length === 0 && <div style="color:var(--muted)">Waiting for events...</div>}
        {lines.map((l, i) => (
          <div key={i} class={l.cls}>
            <span style="color:var(--muted);margin-right:6px">{l.ts}</span>
            {l.text}
          </div>
        ))}
      </div>
    </div>
  );
}
