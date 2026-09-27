import { timingSafeEqual } from 'node:crypto';

// workerd extends SubtleCrypto with timingSafeEqual; Node keeps the same primitive on node:crypto.
Object.assign(crypto.subtle, { timingSafeEqual });
