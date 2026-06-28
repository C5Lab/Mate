import { useState } from 'preact/hooks';
import { Layout } from '../../components/Layout';
import { api } from '../../api';
import { showToast } from '../../components/Toast';

export function SubGhzTesla() {
  const [sending, setSending] = useState(false);
  const [count, setCount] = useState(0);

  async function send() {
    setSending(true);
    try {
      const res = await api.subghzTesla();
      if (res.ok) {
        setCount((c) => c + 1);
        showToast('Tesla charge port signal sent', 'success');
      } else {
        showToast(res.error || 'TX failed', 'error');
      }
    } finally {
      setTimeout(() => setSending(false), 800);
    }
  }

  return (
    <Layout title="Tesla" back="/subghz">
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Charge Port Opener</h3>
          <span class="badge info">315.00 MHz OOK</span>
        </div>

        <div class="kv">
          <div class="kv-row">
            <span class="kv-key">Sent</span>
            <span class="kv-val">{count}</span>
          </div>
        </div>

        <div class="btn-row">
          <button
            class="btn btn-primary btn-block"
            onClick={send}
            disabled={sending}
            style="height:80px;font-size:1.2rem"
          >
            {sending ? <span class="spinner" /> : null}
            {sending ? 'Sending...' : 'Open Charge Port'}
          </button>
        </div>

        <div class="empty-state" style="margin-top:12px">
          Use only on vehicles you own. Transmits a single short OOK burst on 315 MHz.
        </div>
      </section>
    </Layout>
  );
}
