import { route } from 'preact-router';

export function Layout({ title, subtitle, back = '/', actions = null, children }) {
  return (
    <section class="module-page reveal">
      <div class="page-head">
        <div class="page-copy">
          {back && (
            <button class="back-link" onClick={() => route(back)}>
              <span aria-hidden="true">&larr;</span>
              Back
            </button>
          )}
          <h2 class="page-title">{title}</h2>
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}
