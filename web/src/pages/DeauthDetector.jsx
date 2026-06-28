import { useEffect, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { wsAddListener } from '../ws';

function isDeauthPattern(message = '') {
  const lower = message.toLowerCase();
  return (
    lower.includes('deauth') ||
    lower.includes('disassoc') ||
    lower.includes('wlan reason') ||
    lower.includes('beacon flood')
  );
}

export function DeauthDetector() {
  const [armed, setArmed] = useState(true);
  const [events, setEvents] = useState([]);

  useEffect(() => {
    const remove = wsAddListener((msg) => {
      if (!armed) return;

      if (msg.type === 'uart_line' && isDeauthPattern(msg.data)) {
        setEvents((prev) => [
          {
            id: `${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
            ts: Date.now(),
            time: new Date().toLocaleTimeString(),
            details: msg.data,
          },
          ...prev,
        ]);
      }
    });

    return remove;
  }, [armed]);

  const hitsLastMinute = events.filter((event) => Date.now() - event.ts <= 60000).length;

  return (
    <Layout
      title="Deauth Detector"
      subtitle="Passive watchdog for suspicious deauth/disassociation patterns in live telemetry."
      back="/"
    >
      <section class="glass-card card-body reveal">
        <div class="stats-grid" style="grid-template-columns: repeat(3, minmax(0, 1fr));">
          <article class="stat-card">
            <div class="stat-label">Detector</div>
            <div class="stat-value">{armed ? 'Armed' : 'Paused'}</div>
          </article>
          <article class="stat-card">
            <div class="stat-label">Total Events</div>
            <div class="stat-value">{events.length}</div>
          </article>
          <article class="stat-card">
            <div class="stat-label">Recent</div>
            <div class="stat-value">{hitsLastMinute}</div>
          </article>
        </div>

        <div class="btn-row">
          <button class="btn btn-success" onClick={() => setArmed(true)} disabled={armed}>
            Arm
          </button>
          <button class="btn btn-secondary" onClick={() => setArmed(false)} disabled={!armed}>
            Pause
          </button>
          <button class="btn btn-danger" onClick={() => setEvents([])} disabled={!events.length}>
            Clear Events
          </button>
        </div>
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Event Feed</h3>
          <span class="badge info">Pattern-based</span>
        </div>

        {!events.length ? (
          <div class="empty-state">No suspicious events detected yet.</div>
        ) : (
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Signal</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.id}>
                    <td>{event.time}</td>
                    <td>{event.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </Layout>
  );
}
