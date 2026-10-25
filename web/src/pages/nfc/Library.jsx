import { route } from 'preact-router';
import { useEffect, useState } from 'preact/hooks';
import { Layout } from '../../components/Layout';
import { api } from '../../api';
import { showToast } from '../../components/Toast';
import { wsAddListener } from '../../ws';
import { fetchNfcListAfterRefresh } from '../../nfcUtil';

export function NfcLibrary() {
  const [cards, setCards] = useState([]);
  const [loading, setLoading] = useState(false);

  async function refresh() {
    setLoading(true);
    try {
      const res = await fetchNfcListAfterRefresh();
      if (res.ok) setCards(res.cards || []);
      else showToast(res.error || 'List failed', 'error');
    } catch (e) {
      showToast('Failed to load cards', 'error');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  useEffect(() => wsAddListener((msg) => {
    if (msg.type === 'nfc_list_end') {
      api.nfcList().then((res) => {
        if (res.ok) setCards(res.cards || []);
      });
    }
  }), []);

  return (
    <Layout title="NFC Library" back="/nfc">
      <section class="glass-card card-body reveal">
        <div class="section-head">
          <h3 class="section-title">Saved cards</h3>
          <button class="btn btn-soft" onClick={refresh} disabled={loading}>
            {loading ? <span class="spinner" /> : null}
            {loading ? 'Loading...' : 'Refresh'}
          </button>
        </div>
        <div class="kv">
          <div class="kv-row">
            <span class="kv-key">Count</span>
            <span class="kv-val">{cards.length}</span>
          </div>
        </div>
        {cards.length ? (
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Name</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {cards.map((c) => (
                  <tr key={c.idx}>
                    <td>{c.idx}</td>
                    <td>{c.name}</td>
                    <td>
                      <button class="btn btn-primary" onClick={() => route(`/nfc/card/${c.idx}`)}>
                        Open
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div class="empty-state">
            {loading ? 'Loading saved cards...' : 'No saved cards.'}
          </div>
        )}
      </section>
    </Layout>
  );
}
