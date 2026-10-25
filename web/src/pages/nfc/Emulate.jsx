import { useEffect, useState } from 'preact/hooks';
import { Layout } from '../../components/Layout';
import { api } from '../../api';
import { showToast } from '../../components/Toast';
import { wsAddListener } from '../../ws';
import { emulateCapability, normalizeCard, snapshotNfcSeq, waitForNfcEmulate } from '../../nfcUtil';

export function NfcEmulate({ idx }) {
  const [status, setStatus] = useState('Starting…');
  const [detail, setDetail] = useState('');
  const [running, setRunning] = useState(false);
  const back = Number.isFinite(Number(idx)) ? `/nfc/card/${idx}` : '/nfc/library';

  useEffect(() => {
    let cancelled = false;

    async function start() {
      const before = await api.nfcStatus().catch(() => null);
      const done = waitForNfcEmulate(snapshotNfcSeq(before), 5000);
      const res = await api.nfcEmulate();
      if (cancelled) return;
      if (!res?.ok) {
        setRunning(false);
        setStatus('Start failed');
        showToast(res?.error || 'Emulate failed', 'error');
        return;
      }
      const msg = await done;
      if (cancelled) return;
      if (!msg || msg.type === 'nfc_emulate_failed') {
        setRunning(false);
        setStatus('Emulate failed');
        setDetail('Only NFC-A UID emulation is supported');
        return;
      }
      const card = normalizeCard(msg);
      let bus = 'spi';
      try {
        const st = await api.nfcStatus();
        if (st?.ok && st.bus) bus = st.bus;
      } catch (e) { /* status is optional for capability copy */ }
      setRunning(true);
      setStatus('Emulating');
      setDetail([
        card?.emulating || `${card?.type || 'Card'} uid ${card?.uid || ''}`.trim(),
        emulateCapability(card, bus),
      ].filter(Boolean).join('\n'));
    }

    start();

    const remove = wsAddListener((msg) => {
      if (msg.type === 'attack_stopped') {
        setRunning(false);
        setStatus('Stopped');
      }
    });

    return () => {
      cancelled = true;
      remove();
      api.nfcStop().catch(() => {});
    };
  }, [idx]);

  return (
    <Layout title="NFC Emulate" back={back} onBack={() => api.nfcStop()}>
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Listen mode</h3>
          <span class={`badge ${running ? 'ok' : 'warn'}`}>{status}</span>
        </div>
        <p class="empty-state" style="white-space:pre-wrap;text-align:left">
          {detail || 'Starting NFC-A emulation…'}
        </p>
        <p class="module-note">Back sends stop</p>
        {running ? (
          <button
            class="btn btn-danger btn-block"
            onClick={async () => {
              await api.nfcStop();
              setRunning(false);
              setStatus('Stopped');
            }}
          >
            Stop
          </button>
        ) : null}
      </section>
    </Layout>
  );
}
