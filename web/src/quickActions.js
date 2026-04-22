export const QUICK_ACTION_OPTIONS = [
  { id: 'scan', label: 'Scan', icon: 'wifi' },
  { id: 'blackout', label: 'Blackout', icon: 'alert' },
  { id: 'stop', label: 'Stop', icon: 'stop' },
  { id: 'observer', label: 'Observer', icon: 'eye' },
  { id: 'deauth', label: 'Deauth', icon: 'alert' },
  { id: 'eviltwin', label: 'Evil Twin', icon: 'portal' },
  { id: 'mitm', label: 'MITM', icon: 'radar' },
  { id: 'nmap', label: 'Nmap', icon: 'map' },
  { id: 'arp', label: 'ARP', icon: 'ap' },
];

export function quickActionById(id) {
  return QUICK_ACTION_OPTIONS.find((q) => q.id === id) || QUICK_ACTION_OPTIONS[0];
}
