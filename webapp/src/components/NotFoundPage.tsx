import { Home } from 'lucide-preact';
import { t } from '@/lib/i18n';

interface NotFoundPageProps {
  title?: string;
  message?: string;
  homeHref?: string;
}

export default function NotFoundPage(props: NotFoundPageProps) {
  return (
    <main className="not-found-page">
      <section className="not-found-shell" aria-labelledby="not-found-title">
        <div className="not-found-brand">
          <img src="/nodewarden-logo.svg" alt="NodeWarden logo" className="not-found-logo" />
          <span className="not-found-wordmark" aria-label="NodeWarden" role="img" />
        </div>
        <div className="not-found-copy">
          <div className="not-found-code">404</div>
          <h1 id="not-found-title">{props.title || t('txt_page_not_found')}</h1>
          <p>{props.message || t('txt_page_not_found_hint')}</p>
          <a className="btn btn-primary not-found-action" href={props.homeHref || '/'}>
            <Home size={14} className="btn-icon" />
            {t('txt_back_to_home')}
          </a>
        </div>
      </section>
    </main>
  );
}
