import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../components/Layout';
import { api } from '../api';
import { showToast } from '../components/Toast';
import { wsAddListener } from '../ws';

const REFRESH_MS = 1300;

/* Node colour by Zigbee role. Coordinator = the PAN root, routers relay, end
 * devices are leaves. Matches the Tab5 palette intent (distinct, high contrast
 * in both themes). */
function roleColor(role) {
  const r = (role || '').toLowerCase();
  if (r.includes('coord')) return '#a855f7';  // purple
  if (r.includes('router')) return '#22d3ee'; // cyan
  if (r.includes('end')) return '#f59e0b';    // amber
  return '#64748b';                           // slate
}

function roleLabel(role) {
  const r = (role || '').toLowerCase();
  if (r.includes('coord')) return 'Coordinator';
  if (r.includes('router')) return 'Router';
  if (r.includes('end')) return 'End device';
  return role || 'Unknown';
}

/* Deterministic radial layout: coordinator (or the first node) in the middle,
 * everything else evenly spaced on a ring. No physics engine — stable frame to
 * frame so the graph doesn't jitter as the poll refreshes. */
function layoutNodes(nodes) {
  const W = 320;
  const H = 240;
  const cx = W / 2;
  const cy = H / 2;
  const R = Math.min(W, H) * 0.37;

  const pos = {};
  if (!nodes.length) return { pos, W, H };

  let centerIdx = nodes.findIndex((n) => /coord/i.test(n.role || ''));
  if (centerIdx < 0) centerIdx = 0;

  pos[nodes[centerIdx].addr] = { x: cx, y: cy, center: true };
  const others = nodes.filter((_, i) => i !== centerIdx);
  others.forEach((n, k) => {
    const ang = (2 * Math.PI * k) / Math.max(1, others.length) - Math.PI / 2;
    pos[n.addr] = { x: cx + R * Math.cos(ang), y: cy + R * Math.sin(ang), center: false };
  });
  return { pos, W, H };
}

function MeshGraph({ nodes, edges }) {
  if (!nodes.length) {
    return <div class="empty-state">No nodes seen in this PAN yet.</div>;
  }

  const { pos, W, H } = layoutNodes(nodes);

  return (
    <svg
      class="mesh-graph"
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="xMidYMid meet"
      role="img"
      aria-label="Mesh topology graph"
    >
      {edges.map((e, i) => {
        const a = pos[e.from];
        const b = pos[e.to];
        if (!a || !b) return null;
        return (
          <line
            key={`e${i}`}
            x1={a.x}
            y1={a.y}
            x2={b.x}
            y2={b.y}
            stroke="rgba(148,163,184,0.5)"
            stroke-width="1.5"
          />
        );
      })}
      {nodes.map((n) => {
        const p = pos[n.addr];
        if (!p) return null;
        const r = p.center ? 13 : 10;
        return (
          <g key={n.addr}>
            <circle cx={p.x} cy={p.y} r={r} fill={roleColor(n.role)} stroke="#0b1220" stroke-width="2" />
            <text
              x={p.x}
              y={p.y + r + 11}
              text-anchor="middle"
              font-size="10"
              fill="currentColor"
              opacity="0.85"
            >
              {n.addr}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

export function MeshRecon() {
  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState({ channel: 0, packets: 0, pans_seen: 0, dropped: 0, active: false });
  const [pans, setPans] = useState([]);
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [expanded, setExpanded] = useState(null);
  const loopRef = useRef(null);

  async function loadResults() {
    try {
      const d = await api.zigbeeResults();
      if (!d?.ok) return;
      setStatus({
        channel: d.channel || 0,
        packets: d.packets || 0,
        pans_seen: d.pans_seen || (d.pans ? d.pans.length : 0),
        dropped: d.dropped || 0,
        active: !!d.active,
      });
      setPans(Array.isArray(d.pans) ? d.pans : []);
      setNodes(Array.isArray(d.nodes) ? d.nodes : []);
      setEdges(Array.isArray(d.edges) ? d.edges : []);
      if (typeof d.running === 'boolean') setRunning(d.running);
    } catch (e) {
      /* transient — next tick retries */
    }
  }

  function startLoop() {
    if (loopRef.current) return;
    loopRef.current = setInterval(async () => {
      try {
        await api.zigbeeRefresh();
      } catch (e) { /* ignore */ }
      /* Give the Monster a beat to answer the rotating query, then read the
       * parsed cache the firmware accumulated. */
      setTimeout(loadResults, 600);
    }, REFRESH_MS);
  }

  function stopLoop() {
    if (loopRef.current) {
      clearInterval(loopRef.current);
      loopRef.current = null;
    }
  }

  useEffect(() => {
    (async () => {
      try {
        const s = await api.status();
        if (s?.ok && s.state === 'zig_recon') {
          /* Recon already running on the Monster (we reconnected) — resume. */
          setRunning(true);
          startLoop();
        }
      } catch (e) { /* ignore */ }
      loadResults();
    })();

    const removeWs = wsAddListener((msg) => {
      if (msg.type === 'attack_started' && msg.attack === 'zig_recon') {
        setRunning(true);
        startLoop();
      }
      if (msg.type === 'attack_stopped') {
        stopLoop();
        setRunning(false);
      }
    });

    return () => {
      stopLoop();
      removeWs();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function start() {
    const res = await api.zigbeeStart().catch(() => null);
    if (!res?.ok) {
      showToast(res?.error || 'Failed to start Mesh Recon', 'error');
      return;
    }
    setRunning(true);
    setExpanded(null);
    startLoop();
    showToast('Mesh Recon started — sniffing 802.15.4', 'success');
  }

  async function stop() {
    stopLoop();
    await api.stop().catch(() => {});
    setRunning(false);
    /* One last read so the results stay visible after stopping. */
    loadResults();
    showToast('Mesh Recon stopped', 'warning');
  }

  async function clearAll() {
    await api.zigbeeClear().catch(() => {});
    setPans([]);
    setNodes([]);
    setEdges([]);
    setExpanded(null);
    showToast('Mesh data cleared', 'info');
  }

  const nodesFor = (panId) => nodes.filter((n) => n.pan === panId);
  const edgesFor = (panId) => edges.filter((e) => e.pan === panId);

  return (
    <Layout title="Mesh Recon" back="/">
      <section class="glass-card card-body reveal">
        <div class="stats-grid" style="grid-template-columns: repeat(4, minmax(0, 1fr));">
          <article class="stat-card">
            <div class="stat-label">Channel</div>
            <div class="stat-value">{status.channel || '--'}</div>
          </article>
          <article class="stat-card">
            <div class="stat-label">Packets</div>
            <div class="stat-value">{status.packets}</div>
          </article>
          <article class="stat-card">
            <div class="stat-label">Mesh nets</div>
            <div class="stat-value">{pans.length}</div>
          </article>
          <article class="stat-card">
            <div class="stat-label">Dropped</div>
            <div class="stat-value">{status.dropped}</div>
          </article>
        </div>

        <div class="btn-row">
          <button class="btn btn-success" onClick={start} disabled={running}>
            {running ? <><span class="spinner" /> Scanning…</> : 'Start Mesh Recon'}
          </button>
          <button class="btn btn-danger" onClick={stop} disabled={!running}>
            Stop
          </button>
          <button class="btn btn-secondary" onClick={clearAll}>
            Clear
          </button>
        </div>

        <div class="section-note">
          Sniffs Zigbee / 802.15.4 across all channels and maps every PAN, its
          nodes and parent-child links live. Keeps running on the Monster if you
          disconnect.
        </div>
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Mesh Networks</h3>
          <span class={`badge ${running ? 'ok' : ''}`}>{running ? 'Live' : 'Idle'}</span>
        </div>

        {!pans.length ? (
          <div class="empty-state">
            {running ? 'Listening for mesh networks…' : 'No mesh networks yet. Press Start.'}
          </div>
        ) : (
          <ul class="mesh-pan-list">
            {pans.map((pan) => {
              const open = expanded === pan.id;
              const pnodes = nodesFor(pan.id);
              const pedges = edgesFor(pan.id);
              return (
                <li class={`mesh-pan ${open ? 'open' : ''}`} key={pan.id}>
                  <button class="mesh-pan-head" onClick={() => setExpanded(open ? null : pan.id)}>
                    <span class={`mesh-chevron ${open ? 'open' : ''}`}>▸</span>
                    <span class="mesh-pan-id">{pan.id}</span>
                    <span class="mesh-pan-proto" style={`color:${roleColor(pan.proto === 'zigbee' ? 'coord' : '')}`}>
                      {pan.proto || '802.15.4'}
                    </span>
                    <span class="badge">{pnodes.length || pan.nodes || 0} nodes</span>
                    <span class="mesh-pan-rssi">{pan.rssi ? `${pan.rssi} dBm` : ''}</span>
                  </button>

                  {open ? (
                    <div class="mesh-pan-body">
                      <div class="mesh-pan-meta">
                        {pan.channels && pan.channels !== '--' ? (
                          <span class="badge">CH {pan.channels}</span>
                        ) : null}
                        {pan.confidence ? <span class="badge">{pan.confidence}</span> : null}
                        <span class="badge">{pan.packets} pkts</span>
                        <span class="badge">{pedges.length} links</span>
                      </div>

                      <MeshGraph nodes={pnodes} edges={pedges} />

                      <ul class="mesh-node-list">
                        {pnodes.map((n) => (
                          <li class="mesh-node" key={n.addr}>
                            <span class="mesh-node-dot" style={`background:${roleColor(n.role)}`} />
                            <span class="mesh-node-addr">{n.addr}</span>
                            <span class="mesh-node-role">{roleLabel(n.role)}</span>
                            {n.vendor ? <span class="mesh-node-vendor">{n.vendor}</span> : null}
                            <span class="mesh-node-rssi">{n.rssi ? `${n.rssi} dBm` : ''}</span>
                          </li>
                        ))}
                        {!pnodes.length ? (
                          <li class="mesh-node empty">No nodes resolved yet</li>
                        ) : null}
                      </ul>
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </section>
    </Layout>
  );
}
