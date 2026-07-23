import { api } from './api';
import { waitForWs } from './ws';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Issue `subghz_list <source>` and return the cached signal rows once the
 * Mate host has finished parsing the UART reply.
 *
 * The HTTP cache is updated on the device before the WS `subghz_list_end`
 * fires, but the first GET on page load often races ahead of the refresh —
 * which is why Transmit showed "No stored signals" until Refresh was clicked
 * manually (the second GET then hit the already-populated cache). We wait
 * for `subghz_list_end` when WS is up, and poll GET as a fallback.
 */
export async function fetchSubghzListAfterRefresh(source = 'sd', timeoutMs = 4000) {
  const endPromise = waitForWs('subghz_list_end', timeoutMs).catch(() => null);
  const refresh = await api.subghzListRefresh(source);
  if (!refresh?.ok) {
    return { ok: false, signals: [], error: refresh?.error || 'refresh failed' };
  }

  const endMsg = await endPromise;
  const pollUntil = Date.now() + (endMsg ? 600 : timeoutMs);

  let last = [];
  while (Date.now() < pollUntil) {
    const res = await api.subghzList();
    if (res?.ok) {
      last = res.signals || [];
      /* LIST_END received — cache is final (may legitimately be empty). */
      if (endMsg) return { ok: true, signals: last };
      if (last.length > 0) return { ok: true, signals: last };
    }
    await sleep(120);
  }

  const res = await api.subghzList();
  if (res?.ok) return { ok: true, signals: res.signals || [] };
  return { ok: true, signals: last };
}

/** Merge HTTP/WS signal rows into a table keyed by idx (newest first). */
export function mergeSubghzSignals(prev, incoming, max = 200) {
  const byIdx = new Map();
  for (const s of prev) byIdx.set(s.idx, s);
  for (const s of incoming) {
    byIdx.set(s.idx, { ...s, signalType: s.signalType || s.type });
  }
  return [...byIdx.values()]
    .sort((a, b) => b.idx - a.idx)
    .slice(0, max);
}
