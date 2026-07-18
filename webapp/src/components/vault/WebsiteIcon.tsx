import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import type { ComponentChildren } from 'preact';
import { Globe } from 'lucide-preact';
import type { Cipher } from '@/lib/types';
import {
  beginWebsiteIconLoad,
  getWebsiteIconImageUrl,
  getWebsiteIconStatus,
  subscribeWebsiteIconStatus,
} from '@/lib/website-icon-cache';
import { demoBrandIconUrl } from '@/lib/demo-brand-icons';
import { getCurrentNetworkStatus, subscribeNetworkStatus } from '@/lib/network-status';
import { areWebsiteIconsEnabled } from '@/lib/website-icon-settings';
import { firstCipherUri, hostFromUri, websiteIconUrl } from '@/lib/website-utils';

const ICON_LOAD_ROOT_MARGIN = '180px 0px';
const SHOULD_LOAD_DEMO_BRAND_ICONS = __NODEWARDEN_DEMO__;

interface WebsiteIconProps {
  cipher: Cipher;
  fallback?: ComponentChildren;
}

export default function WebsiteIcon(props: WebsiteIconProps) {
  const host = useMemo(() => hostFromUri(firstCipherUri(props.cipher)), [props.cipher]);
  const iconsEnabled = areWebsiteIconsEnabled();
  const src = iconsEnabled && host ? websiteIconUrl(host) : '';
  const nodeRef = useRef<HTMLSpanElement | null>(null);
  const [shouldLoad, setShouldLoad] = useState(() => (host ? getWebsiteIconStatus(host) === 'loaded' : true));
  const [status, setStatus] = useState(() => (host ? getWebsiteIconStatus(host) : 'idle'));
  const [imageUrl, setImageUrl] = useState(() => (host ? getWebsiteIconImageUrl(host) : ''));
  const [networkStatus, setNetworkStatus] = useState(getCurrentNetworkStatus);
  const demoIconUrl = SHOULD_LOAD_DEMO_BRAND_ICONS && host ? demoBrandIconUrl(host) : '';

  useEffect(() => subscribeNetworkStatus(setNetworkStatus), []);

  useEffect(() => {
    if (!host || !iconsEnabled) {
      setShouldLoad(true);
      setStatus('idle');
      setImageUrl('');
      return;
    }
    const nextStatus = getWebsiteIconStatus(host);
    setShouldLoad(nextStatus === 'loaded');
    setStatus(nextStatus);
    setImageUrl(getWebsiteIconImageUrl(host));
    return subscribeWebsiteIconStatus(host, (next) => {
      setStatus(next);
      setImageUrl(getWebsiteIconImageUrl(host));
    });
  }, [host, iconsEnabled]);

  useEffect(() => {
    if (!host || shouldLoad || status === 'loaded' || status === 'error') return;
    const node = nodeRef.current;
    if (!node) return;
    if (typeof IntersectionObserver !== 'function') {
      setShouldLoad(true);
      return;
    }

    let cancelled = false;
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting && entry.intersectionRatio <= 0) continue;
          if (!cancelled) setShouldLoad(true);
          observer.disconnect();
          break;
        }
      },
      { rootMargin: ICON_LOAD_ROOT_MARGIN }
    );

    observer.observe(node);
    return () => {
      cancelled = true;
      observer.disconnect();
    };
  }, [host, shouldLoad, status]);

  useEffect(() => {
    if (SHOULD_LOAD_DEMO_BRAND_ICONS) return;
    if (demoIconUrl) return;
    if (!iconsEnabled) return;
    if (networkStatus !== 'online') return;
    if (!host || !src || !shouldLoad || status !== 'idle') return;
    beginWebsiteIconLoad(host, src);
  }, [demoIconUrl, host, iconsEnabled, networkStatus, src, shouldLoad, status]);

  if (demoIconUrl) {
    return (
      <span className="list-icon-stack" ref={nodeRef}>
        <img
          className="list-icon loaded"
          src={demoIconUrl}
          alt=""
          loading="lazy"
          decoding="async"
        />
      </span>
    );
  }

  if (!host || !iconsEnabled || status === 'error') {
    return <span className="list-icon-fallback">{props.fallback ?? <Globe size={18} />}</span>;
  }

  const shouldRenderIconImage = !!imageUrl && status === 'loaded';

  return (
    <span className="list-icon-stack" ref={nodeRef}>
      {status !== 'loaded' && <span className="list-icon-fallback">{props.fallback ?? <Globe size={18} />}</span>}
      {shouldRenderIconImage && (
        <img
          className={`list-icon${status === 'loaded' ? ' loaded' : ''}`}
          src={imageUrl}
          alt=""
          loading="lazy"
          decoding="async"
        />
      )}
    </span>
  );
}

