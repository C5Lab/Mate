export function NetworkList({ networks, selected, onToggle, onToggleAll }) {
  if (!networks || networks.length === 0) {
    return <div class="empty-msg">No networks. Run a scan first.</div>;
  }

  const allSelected = networks.every(n => selected.has(n.index));

  function rssiClass(rssi) {
    if (rssi > -50) return 'rssi-good';
    if (rssi > -70) return 'rssi-med';
    return 'rssi-weak';
  }

  return (
    <div class="panel">
      <div class="panel-header">
        <span>Networks ({networks.length})</span>
        {onToggleAll && (
          <button class="btn btn-sm btn-magenta" onClick={() => onToggleAll(!allSelected)}>
            {allSelected ? 'Deselect All' : 'Select All'}
          </button>
        )}
      </div>
      <div class="panel-body" style="max-height:50vh;overflow-y:auto">
        {networks.map(n => (
          <div class="net-row" key={n.index} onClick={() => onToggle(n.index)}>
            <input
              type="checkbox"
              class="net-cb"
              checked={selected.has(n.index)}
              onClick={e => e.stopPropagation()}
              onChange={() => onToggle(n.index)}
            />
            <div class="net-info">
              <div class="net-ssid">{n.ssid || '[Hidden]'}</div>
              <div class="net-meta">
                {n.bssid} | CH{n.channel} | {n.security} | {n.band}
              </div>
            </div>
            <div class={`net-rssi ${rssiClass(n.rssi)}`}>{n.rssi}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
