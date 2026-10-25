import { useEffect, useRef, useState } from 'preact/hooks';
import { Layout } from '../../components/Layout';
import { api } from '../../api';
import { showToast } from '../../components/Toast';
import { wsAddListener } from '../../ws';
import { nfcNameIsValid, normalizeCard, snapshotNfcSeq, waitForNfcRead } from '../../nfcUtil';

const READ_TIMEOUT_MS = 20000;

export function NfcRead() {
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState('Idle');
  const [card, setCard] = useState(null);
  const [saveOpen, setSaveOpen] = useState(false);
  const [saveName, setSaveName] = useState('');
  const [saving, setSaving] = useState(false);
  const pendingRef = useRef(false);

  useEffect(() => {
    const remove = wsAddListener((msg) => {
      if (msg.type === 'nfc_read_progress') {
        if (msg.present) setStatus('Present a card…');
        else if (msg.cardType) setStatus(msg.cardType);
      } else if (msg.type === 'nfc_read_done') {
        pendingRef.current = false;
        setBusy(false);
        const next = normalizeCard(msg);
        if (msg.noCard || msg.timeout) {
          setCard(null);
          setStatus(msg.timeout ? 'Timed out' : 'No card detected');
        } else {
          setCard(next);
          setStatus(next.type || 'Card');
        }
      } else if (msg.type === 'nfc_save_done') {
        setSaving(false);
        setSaveOpen(false);
        showToast(`Saved ${msg.path || saveName}`, 'success');
      } else if (msg.type === 'nfc_save_err') {
        setSaving(false);
        showToast(msg.reason === 'nothing_to_save' ? 'Read a card first' : (msg.reason || 'Save failed'), 'error');
      }
    });
    return () => remove();
  }, [saveName]);

  async function readCard() {
    if (busy) return;
    setBusy(true);
    setCard(null);
    setStatus('Present a card…');
    pendingRef.current = true;
    try {
      const before = await api.nfcStatus().catch(() => null);
      const seq0 = snapshotNfcSeq(before);
      const done = waitForNfcRead(seq0, READ_TIMEOUT_MS);
      const res = await api.nfcRead();
      if (!res?.ok) {
        pendingRef.current = false;
        setBusy(false);
        setStatus('Idle');
        showToast(res?.error || 'Read failed', 'error');
        return;
      }
      const msg = await done;
      if (!pendingRef.current) return;
      pendingRef.current = false;
      setBusy(false);
      if (!msg || msg.noCard || msg.timeout) {
        setCard(null);
        setStatus(msg?.timeout ? 'Timed out' : (msg ? 'No card detected' : 'Timed out'));
      } else {
        const next = normalizeCard(msg);
        setCard(next);
        setStatus(next.type || 'Card');
      }
    } catch (e) {
      pendingRef.current = false;
      setBusy(false);
      setStatus('Idle');
      showToast('Read failed', 'error');
    }
  }

  async function saveCard() {
    const name = saveName.trim();
    if (!nfcNameIsValid(name)) {
      showToast('Use letters, digits, _ - .', 'warning');
      return;
    }
    setSaving(true);
    const res = await api.nfcSave(name);
    if (!res?.ok) {
      setSaving(false);
      showToast(res?.error || 'Save failed', 'error');
    }
  }

  const haveCard = !!(card && (card.uid || card.type));

  return (
    <Layout title="NFC Read" back="/nfc">
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Card</h3>
          <span class={`badge ${busy ? 'info' : haveCard ? 'ok' : ''}`}>
            {busy ? 'Reading' : status}
          </span>
        </div>

        {busy ? (
          <div class="empty-state">
            <span class="spinner" />
            Present a card…
          </div>
        ) : haveCard ? (
          <div class="kv">
            <div class="kv-row"><span class="kv-key">Type</span><span class="kv-val">{card.type || '—'}</span></div>
            <div class="kv-row"><span class="kv-key">UID</span><span class="kv-val">{card.uid || '—'}</span></div>
            {card.haveAtqaSak ? (
              <div class="kv-row">
                <span class="kv-key">ATQA / SAK</span>
                <span class="kv-val">
                  {Number(card.atqa0).toString(16).padStart(2, '0')} {Number(card.atqa1).toString(16).padStart(2, '0')}
                  {' / '}
                  {Number(card.sak).toString(16).padStart(2, '0')}
                </span>
              </div>
            ) : null}
            {card.haveIdm ? (
              <div class="kv-row"><span class="kv-key">IDm</span><span class="kv-val">{card.idm}</span></div>
            ) : null}
            {card.haveData ? (
              <div class="kv-row">
                <span class="kv-key">Data</span>
                <span class="kv-val">{card.dataLen || 0} bytes dumped</span>
              </div>
            ) : null}
          </div>
        ) : (
          <div class="empty-state">{status === 'Idle' ? 'Tap Read, then present a card.' : status}</div>
        )}

        <div class="btn-row">
          <button class="btn btn-info" onClick={readCard} disabled={busy}>
            {busy ? <span class="spinner" /> : null}
            {busy ? 'Reading...' : 'Read'}
          </button>
          <button
            class="btn btn-success"
            disabled={!haveCard || busy}
            onClick={() => { setSaveName(''); setSaveOpen(true); }}
          >
            Save
          </button>
        </div>
      </section>

      {saveOpen ? (
        <div class="scan-modal-overlay" onClick={() => !saving && setSaveOpen(false)}>
          <section class="glass-card scan-modal scan-modal-compact" onClick={(e) => e.stopPropagation()}>
            <div class="scan-modal-head">
              <h3 class="section-title">Save card</h3>
            </div>
            <div class="field">
              <label class="field-label">Name</label>
              <input
                class="input"
                value={saveName}
                maxlength={48}
                placeholder="office_badge"
                onInput={(e) => setSaveName(e.currentTarget.value)}
              />
            </div>
            <div class="btn-row">
              <button class="btn btn-success" disabled={saving} onClick={saveCard}>
                {saving ? <span class="spinner" /> : null}
                Save
              </button>
              <button class="btn btn-soft" disabled={saving} onClick={() => setSaveOpen(false)}>Cancel</button>
            </div>
          </section>
        </div>
      ) : null}
    </Layout>
  );
}
