function signalClass(rssi) {
  if (rssi >= -55) return 'good';
  if (rssi >= -72) return 'medium';
  return 'weak';
}

export function NetworkList({ networks, selected, onToggle, onToggleAll }) {
  if (!networks || networks.length === 0) {
    return <div class="empty-state">No scan data yet. Start a scan to discover nearby APs.</div>;
  }

  const allSelected = networks.every((n) => selected.has(n.index));

  return (
    <section class="network-panel reveal">
      <div class="network-head">
        <span class="count-pill">Networks: {networks.length}</span>
        {onToggleAll && (
          <button class="soft-btn" onClick={() => onToggleAll(!allSelected)}>
            {allSelected ? 'Clear Selection' : 'Select All'}
          </button>
        )}
      </div>

      <div class="network-scroll">
        {networks.map((n) => {
          const barClass = signalClass(n.rssi);
          return (
            <label class="network-row" key={n.index}>
              <span class="checkbox-wrap">
                <input
                  type="checkbox"
                  class="network-check"
                  checked={selected.has(n.index)}
                  onChange={() => onToggle(n.index)}
                />
              </span>

              <span class="network-main">
                <span class="network-title">{n.ssid || '[Hidden Network]'}</span>
                {n.vendor ? <span class="network-meta">{n.vendor}</span> : null}
                <span class="network-meta network-mac">{n.bssid}</span>
                <span class="network-meta">CH{n.channel} | {n.security || 'Open'} | {n.band || '2.4G'}</span>
              </span>

              <span class="signal-wrap">
                <span class={`signal-bars ${barClass}`}>
                  <span />
                  <span />
                  <span />
                  <span />
                </span>
                <span class="signal-value">{n.rssi} dBm</span>
              </span>
            </label>
          );
        })}
      </div>
    </section>
  );
}
