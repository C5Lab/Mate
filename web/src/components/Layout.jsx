import { route } from 'preact-router';

export function Layout({ title, back, children }) {
  return (
    <div>
      {back && (
        <button class="back-btn" onClick={() => route(back)}>
          &larr; Back
        </button>
      )}
      {title && <div class="page-title">{title}</div>}
      {children}
    </div>
  );
}
