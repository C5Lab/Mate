/**
 * Shared Capture Gateway (GITM) live-status panel. Renders the firmware-parsed
 * `[CGW]` snapshot from GET /api/gitm/status (the source of truth, robust to WS
 * drops) plus the `[PCAP_FINAL]` summary once a session has stopped. Used by
 * both the GITM and Rogue GITM pages.
 */

function fileBasename(path) {
  if (!path) return '';
  const slash = path.lastIndexOf('/');
  return slash >= 0 ? path.slice(slash + 1) : path;
}

function humanBytes(n) {
  const b = Number(n) || 0;
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 * 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(1)} MB`;
  return `${(b / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function CgwLive({ snap, final }) {
  const s = snap || {};
  const recorderDegraded = (s.drops || 0) > 0;
  const shaperDegraded = (s.rate_queue_drops || 0) > 0;
  const clients = Array.isArray(s.clients) ? s.clients : [];
  const secLabel = s.security === 'wpa2' ? 'WPA2' : (s.security === 'open' ? 'Open' : (s.security || '-'));

  return (
    <>
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Gateway</h3>
          <span class={`badge ${s.active ? 'ok' : 'info'}`}>
            {s.active ? 'Active' : (s.complete ? 'Idle' : 'Waiting...')}
          </span>
        </div>

        <div class="btn-row" style="flex-wrap:wrap;gap:6px;">
          <span class={`badge ${s.upstream ? 'ok' : 'warn'}`}>
            Upstream {s.upstream ? 'up' : 'down'}
          </span>
          <span class={`badge ${s.napt ? 'ok' : 'warn'}`}>
            NAPT {s.napt ? 'on' : 'off'}
          </span>
          <span class={`badge ${s.capture_active ? 'ok' : 'warn'}`}>
            PCAP {s.capture_active ? 'recording' : 'idle'}
          </span>
          <span class="badge info">CH {s.channel || '-'}</span>
          <span class="badge info">{clients.length} client{clients.length === 1 ? '' : 's'}</span>
        </div>

        <div class="kv">
          <div class="kv-row">
            <span class="kv-key">AP SSID</span>
            <span class="kv-val">{s.ssid || '-'} <span class="badge info">{secLabel}</span></span>
          </div>
          <div class="kv-row">
            <span class="kv-key">Upstream SSID</span>
            <span class="kv-val">{s.upstream_ssid || '-'}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">AP IP</span>
            <span class="kv-val">{s.ap_ip || '-'}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">STA IP</span>
            <span class="kv-val">{s.sta_ip || '-'}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">DNS</span>
            <span class="kv-val">{s.dns || '-'}{s.dns_proxy ? ' (proxy)' : ''}</span>
          </div>
        </div>
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Capture</h3>
          {recorderDegraded ? <span class="badge warn">recorder drops</span>
            : shaperDegraded ? <span class="badge warn">shaper drops</span>
            : <span class="badge ok">healthy</span>}
        </div>
        <div class="kv">
          <div class="kv-row">
            <span class="kv-key">File</span>
            <span class="kv-val">{fileBasename(s.file) || '-'}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">Packets</span>
            <span class="kv-val">{s.packets || 0}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">Recorder drops</span>
            <span class="kv-val">{s.drops || 0}{recorderDegraded ? ' ⚠' : ''}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">Shaper drops</span>
            <span class="kv-val">{s.rate_queue_drops || 0}{shaperDegraded ? ' ⚠' : ''}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">File size</span>
            <span class="kv-val">{humanBytes(s.file_bytes)}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">Rate limit</span>
            <span class="kv-val">
              {s.rate_effective_kbps || 0} / {s.rate_limit_kbps || 0} kbps
              {s.adaptive ? ' (adaptive)' : ''}
            </span>
          </div>
        </div>
      </section>

      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Clients</h3>
          <span class="badge info">{clients.length}{s.clients_truncated ? '+' : ''}</span>
        </div>
        {clients.length ? (
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>#</th><th>MAC</th><th>IP</th></tr></thead>
              <tbody>
                {clients.map((c, i) => (
                  <tr key={c.mac || i}>
                    <td>{i + 1}</td>
                    <td>{c.mac}</td>
                    <td>{c.ip || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div class="empty-state">No clients joined yet.</div>
        )}
      </section>

      {final && final.valid ? (
        <section class="glass-card card-body reveal">
          <div class="section-head">
            <h3 class="section-title">PCAP saved</h3>
            <span class={`badge ${(final.drops || 0) > 0 ? 'warn' : 'ok'}`}>
              {final.frames || 0} frames
            </span>
          </div>
          <div class="kv">
            <div class="kv-row">
              <span class="kv-key">File</span>
              <span class="kv-val">{fileBasename(final.file) || '-'}</span>
            </div>
            <div class="kv-row">
              <span class="kv-key">Path</span>
              <span class="kv-val">{final.file || '-'}</span>
            </div>
            <div class="kv-row">
              <span class="kv-key">Dropped frames</span>
              <span class="kv-val">{final.drops || 0}</span>
            </div>
          </div>
        </section>
      ) : null}
    </>
  );
}
