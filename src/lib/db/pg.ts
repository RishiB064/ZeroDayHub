import { Pool } from "pg";
import type { AppRole } from "./mysql";

/**
 * PostgreSQL / pgvector connections.
 * Asset_Owner sessions use the READ-ONLY database role; analysts and admins use the
 * writer role. Privileges are enforced by PostgreSQL itself (see db/pg/03_roles.sql.tpl).
 */
type PgKey = "reader" | "writer";
const g = globalThis as unknown as { __zdhPg?: Partial<Record<PgKey, Pool>> };

function env(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing environment variable ${name}`);
  return v;
}

export function pgKeyForRole(role: AppRole): PgKey {
  return role === "Asset_Owner" ? "reader" : "writer";
}

export function getPgPool(key: PgKey): Pool {
  const pools = (g.__zdhPg ??= {});
  let pool = pools[key];
  if (!pool) {
    pool = new Pool({
      host: env("PG_HOST"),
      port: Number(process.env.PG_PORT ?? 5432),
      database: env("PG_DATABASE"),
      user: key === "reader" ? env("PG_READER_USER") : env("PG_WRITER_USER"),
      password: key === "reader" ? env("PG_READER_PASSWORD") : env("PG_WRITER_PASSWORD"),
      max: 5,
    });
    pools[key] = pool;
  }
  return pool;
}

/** pgvector text literal, e.g. [0.1,0.2,...] (bound as a parameter, cast with ::vector) */
export function toVectorLiteral(v: number[]): string {
  return `[${v.join(",")}]`;
}
