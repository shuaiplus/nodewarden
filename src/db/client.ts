import { drizzle } from 'drizzle-orm/d1';

import { relations } from './relations';

export type Orm = ReturnType<typeof drizzle<typeof relations, D1Database>>;

// D1 rejects any statement that binds more than this many parameters.
export const D1_MAX_BOUND_PARAMETERS = 100;

// Constructing the driver is cheap, but the relation graph it derives is not:
// memoise per binding so a Worker isolate builds it at most once per database.
const ormByBinding = new WeakMap<D1Database, Orm>();

export function getOrm(d1: D1Database): Orm {
  const existing = ormByBinding.get(d1);
  if (existing) return existing;

  const orm = drizzle(d1, { relations });
  ormByBinding.set(d1, orm);
  return orm;
}
