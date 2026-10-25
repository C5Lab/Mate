import { route } from 'preact-router';
import { useEffect, useState } from 'preact/hooks';
import { Layout } from '../../components/Layout';
import { api } from '../../api';
import { showToast } from '../../components/Toast';
import { wsAddListener } from '../../ws';
import { fetchNfcListAfterRefresh, nfcNameIsValid, normalizeCard, snapshotNfcSeq, waitForNfcLoad } from '../../nfcUtil';

export function NfcDetail({ idx }) {
  const index = Number.parseInt(idx, 10);
  const [status, setStatus] = useState('Loading…');
  const [card, setCard] = useState(null);
  const [name, setName] = useState(`#${idx}`);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(true);
  const [renameOpen, setRenameOpen] = useState(false);
  const [renameName, setRenameName] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(false);

  async function loadCard() {
    if (!Number.isFinite(index) || index < 0) {
      setStatus('Bad index');
      setBusy(false);
      return;
    }
    setBusy(true);
    setLoaded(false);
    try {
      const before = await api.nfcStatus().catch(() => null);
      const done = waitForNfcLoad(snapshotNfcSeq(before), 5000);
      const res = await api.nfcLoad(index);
      if (!res?.ok) {
        setStatus('Load failed');
        showToast(res?.error || 'Load failed', 'error');
        setBusy(false);
        return;
      }
      const msg = await done;
      if (!msg || msg.type === 'nfc_load_err') {
        setCard(null);
        setLoaded(false);
        setStatus('Load failed');
      } else {
        const next = normalizeCard(msg);
        setCard(next);
        setLoaded(true);
        setStatus(next.type || 'Card');
        if (msg.path) {
          const base = String(msg.path).split('/').pop() || '';
          setName(base.replace(/\.nfc$/i, '') || `#${index}`);
        }
      }
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    loadCard();
  }, [index]);

  useEffect(() => wsAddListener((msg) => {
    if (msg.type === 'nfc_rename_done') {
      const base = String(msg.to || '').split('/').pop() || '';
      setName(base.replace(/\.nfc$/i, '') || name);
      setRenameOpen(false);
      showToast('Renamed', 'success');
      fetchNfcListAfterRefresh().catch(() => {});
    } else if (msg.type === 'nfc_rename_err') {
      showToast(msg.error || 'Rename failed', 'error');
    } else if (msg.type === 'nfc_delete_done') {
      showToast('Deleted', 'success');
      route('/nfc/library');
    } else if (msg.type === 'nfc_delete_err') {
      showToast(msg.error || 'Delete failed', 'error');
    }
  }), [name]);

  async function renameCard() {
    const next = renameName.trim();
    if (!nfcNameIsValid(next)) {
      showToast('Use letters, digits, _ - .', 'warning');
      return;
    }
    const res = await api.nfcRename(index, next);
    if (!res?.ok) showToast(res?.error || 'Rename failed', 'error');
  }

  async function deleteCard() {
    setConfirmDelete(false);
    const res = await api.nfcDelete(index);
    if (!res?.ok) showToast(res?.error || 'Delete failed', 'error');
  }

  function goEmulate() {
    if (!loaded) return;
    route(`/nfc/emulate/${index}`);
  }

  return (
    <Layout title="NFC Card" back="/nfc/library">
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">{name}</h3>
          <span class={`badge ${loaded ? 'ok' : busy ? 'info' : 'warn'}`}>{status}</span>
        </div>
        {card && loaded ? (
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
            {card.haveData ? (
              <div class="kv-row">
                <span class="kv-key">Data</span>
                <span class="kv-val">{card.dataLen || 0} bytes dumped</span>
              </div>
            ) : null}
          </div>
        ) : (
          <div class="empty-state">{busy ? 'Loading…' : status}</div>
        )}

        <div class="btn-row">
          <button class="btn btn-primary" disabled={!loaded} onClick={goEmulate}>Emulate</button>
          <button
            class="btn btn-info"
            disabled={busy}
            onClick={() => { setRenameName(name); setRenameOpen(true); }}
          >
            Rename
          </button>
          <button class="btn btn-danger" disabled={busy} onClick={() => setConfirmDelete(true)}>Delete</button>
        </div>
      </section>

      {renameOpen ? (
        <div class="scan-modal-overlay" onClick={() => setRenameOpen(false)}>
          <section class="glass-card scan-modal scan-modal-compact" onClick={(e) => e.stopPropagation()}>
            <div class="scan-modal-head">
              <h3 class="section-title">Rename card</h3>
            </div>
            <div class="field">
              <label class="field-label">New name</label>
              <input
                class="input"
                value={renameName}
                maxlength={48}
                onInput={(e) => setRenameName(e.currentTarget.value)}
              />
            </div>
            <div class="btn-row">
              <button class="btn btn-info" onClick={renameCard}>Rename</button>
              <button class="btn btn-soft" onClick={() => setRenameOpen(false)}>Cancel</button>
            </div>
          </section>
        </div>
      ) : null}

      {confirmDelete ? (
        <div class="settings-overlay" onClick={() => setConfirmDelete(false)}>
          <section class="glass-card settings-panel" onClick={(e) => e.stopPropagation()}>
            <div class="section-head">
              <h3 class="section-title">Delete {name}?</h3>
            </div>
            <p>Removes the file from SD. A loaded/emulated copy in RAM is kept until you leave.</p>
            <div class="btn-row">
              <button class="btn btn-soft" onClick={() => setConfirmDelete(false)}>Cancel</button>
              <button class="btn btn-danger" onClick={deleteCard}>Delete</button>
            </div>
          </section>
        </div>
      ) : null}
    </Layout>
  );
}
