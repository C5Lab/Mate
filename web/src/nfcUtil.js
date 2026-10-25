import { api } from './api';
import { waitForWs, wsAddListener } from './ws';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function nfcNameIsValid(name) {
  return typeof name === 'string' && /^[A-Za-z0-9_.-]+$/.test(name);
}

export function normalizeCard(c) {
  if (!c) return null;
  /* WS nfc_* events put the event name in `type` and the tag family in
   * `cardType`. HTTP /api/nfc/status.last uses `type` for the tag family. */
  const type = c.cardType || (!String(c.type || '').startsWith('nfc_') ? (c.type || '') : '');
  return {
    ...c,
    type,
    cardType: c.cardType || type,
  };
}

export function cardHasDump(c) {
  const card = normalizeCard(c);
  return !!(card && (card.uid || card.type) && !card.noCard);
}

export function emulateCapability(card, bus) {
  const c = normalizeCard(card) || {};
  if (c.emulateFullUl) return 'NTAG/Ultralight page data';
  if (c.emulateUidOnly || bus === 'i2c') {
    return c.classic
      ? 'UID/ATQA/SAK only. Classic Crypto1 is not emulated.'
      : 'UID/ATQA/SAK only';
  }
  if (c.ultralight && c.haveData) return 'NTAG/Ultralight page data';
  return c.classic
    ? 'UID/ATQA/SAK only. Classic Crypto1 is not emulated.'
    : 'UID/ATQA/SAK only';
}

export function waitForNfc(types, timeoutMs) {
  const set = new Set(Array.isArray(types) ? types : [types]);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      remove();
      reject(new Error(`nfc timeout: ${[...set].join(',')}`));
    }, timeoutMs);
    const remove = wsAddListener((msg) => {
      if (set.has(msg.type)) {
        clearTimeout(timer);
        remove();
        resolve(msg);
      }
    });
  });
}

function statusToReadDone(st) {
  const last = st?.last || {};
  const cardType = last.cardType || last.type || '';
  return {
    ...last,
    type: 'nfc_read_done',
    cardType,
    noCard: !!last.noCard,
    timeout: !!st.timeout,
  };
}

function statusToLoadDone(st) {
  const loaded = st?.loaded || {};
  const cardType = loaded.cardType || loaded.type || '';
  if (loaded.loadFailed || loaded.notFound || (!loaded.uid && !loaded.type && !loaded.path && !loaded.haveLoaded)) {
    return {
      type: 'nfc_load_err',
      error: loaded.error || 'load_failed',
    };
  }
  return {
    ...loaded,
    type: 'nfc_load_done',
    cardType,
  };
}

function statusToEmulateDone(st) {
  const loaded = st?.loaded || {};
  const cardType = loaded.cardType || loaded.type || '';
  if (st.emulating) {
    return {
      ...loaded,
      type: 'nfc_emulate_started',
      cardType,
      emulating: loaded.emulating || '',
    };
  }
  return {
    type: 'nfc_emulate_failed',
    error: loaded.error || 'emulate_failed',
  };
}

/** Wait for a WS NFC event, falling back to GET /api/nfc/status when seq advances. */
export async function waitForNfcOp(types, timeoutMs, seq0, interpretStatus) {
  let settled = false;
  const ws = waitForNfc(types, timeoutMs)
    .then((msg) => {
      settled = true;
      return msg;
    })
    .catch(() => null);

  const poll = (async () => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (settled) return null;
      try {
        const st = await api.nfcStatus();
        if (st?.ok && typeof st.seq === 'number' && st.seq > seq0) {
          const msg = interpretStatus(st);
          if (msg) {
            settled = true;
            return msg;
          }
        }
      } catch (e) {
        /* next tick */
      }
      await sleep(250);
    }
    return null;
  })();

  const first = await Promise.race([ws, poll]);
  if (first) return first;
  const rest = await Promise.all([ws, poll]);
  return rest.find(Boolean) || null;
}

export function snapshotNfcSeq(st) {
  return typeof st?.seq === 'number' ? st.seq : Number.POSITIVE_INFINITY;
}

/** Wait for nfc_read_done via WS, falling back to GET /api/nfc/status. */
export async function waitForNfcRead(seq0, timeoutMs) {
  return waitForNfcOp(['nfc_read_done'], timeoutMs, seq0, (st) => {
    if (st.lastOp && st.lastOp !== 'read') return null;
    return statusToReadDone(st);
  });
}

export async function waitForNfcLoad(seq0, timeoutMs = 5000) {
  return waitForNfcOp(['nfc_load_done', 'nfc_load_err'], timeoutMs, seq0, (st) => {
    if (st.lastOp && st.lastOp !== 'load') return null;
    return statusToLoadDone(st);
  });
}

export async function waitForNfcEmulate(seq0, timeoutMs = 5000) {
  return waitForNfcOp(
    ['nfc_emulate_started', 'nfc_emulate_failed'],
    timeoutMs,
    seq0,
    (st) => {
      if (st.lastOp && st.lastOp !== 'emulate') return null;
      return statusToEmulateDone(st);
    }
  );
}

export async function fetchNfcListAfterRefresh(timeoutMs = 5000) {
  const endPromise = waitForWs('nfc_list_end', timeoutMs).catch(() => null);
  const refresh = await api.nfcListRefresh();
  if (!refresh?.ok) {
    return { ok: false, cards: [], error: refresh?.error || 'refresh failed' };
  }

  const endMsg = await endPromise;
  const pollUntil = Date.now() + (endMsg ? 600 : timeoutMs);

  let last = [];
  while (Date.now() < pollUntil) {
    const res = await api.nfcList();
    if (res?.ok) {
      last = res.cards || [];
      if (endMsg) return { ok: true, cards: last };
      if (last.length > 0) return { ok: true, cards: last };
    }
    await sleep(120);
  }

  const res = await api.nfcList();
  if (res?.ok) return { ok: true, cards: res.cards || [] };
  return { ok: true, cards: last };
}
