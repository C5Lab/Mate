import { useEffect, useRef, useState } from 'preact/hooks';
import { wsAddListener } from '../ws';
import { api } from '../api';

/**
 * Live serial console. Reads raw UART lines from the firmware ring buffer over
 * HTTP polling (reliable even when the WebSocket drops frames), and uses WS
 * only for the cosmetic running badge. `attackType` scopes the badge to a
 * specific attack; omit to react to any.
 */
export function AttackMonitor({ title, attackType }) {
  const [lines, setLines] = useState([]);
  const [running, setRunning] = useState(false);
  const logRef = useRef(null);
  const seqRef = useRef(0);

  useEffect(() => {
    let alive = true;

    const scrollDown = () => {
      setTimeout(() => {
        if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
      }, 20);
    };

    const poll = async () => {
      try {
        const res = await api.serialTail(seqRef.current);
        if (!alive || !res || !res.ok) return;
        seqRef.current = res.seq || 0;
        if (Array.isArray(res.lines) && res.lines.length) {
          setLines((prev) => [...prev, ...res.lines].slice(-250));
          scrollDown();
        }
      } catch (e) { /* ignore */ }
    };
    poll();
    const id = setInterval(poll, 800);

    const removeWs = wsAddListener((msg) => {
      if (msg.type === 'attack_started' && (!attackType || msg.attack === attackType)) setRunning(true);
      if (msg.type === 'attack_stopped') setRunning(false);
    });

    return () => { alive = false; clearInterval(id); removeWs(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attackType]);

  return (
    <section class="log-card reveal">
      <header class="log-head">
        <span class="log-title">{title || 'Serial'}</span>
        <span class={`badge ${running ? 'ok' : 'info'}`}>
          {running ? <span class="spinner" /> : null}
          {running ? 'Live' : 'Monitoring'}
        </span>
      </header>
      <div class="log-stream" ref={logRef}>
        {lines.length === 0 ? (
          <div class="log-empty">Waiting for serial output…</div>
        ) : (
          lines.map((text, index) => (
            <div key={index} class="log-line">{text}</div>
          ))
        )}
      </div>
    </section>
  );
}
