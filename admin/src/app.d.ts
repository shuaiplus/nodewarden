import type { AdminPortal, AdminSession } from '../../src/admin/portal-contract';

declare global {
  namespace App {
    interface Platform {
      portal: AdminPortal;
    }
    interface Locals {
      // Set by hooks.server.ts for every page outside the sign-in flow.
      session?: AdminSession;
      // Set before a 429 so the response carries Retry-After.
      retryAfterSeconds?: number;
    }
  }
}

export {};
