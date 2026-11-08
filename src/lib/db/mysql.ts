import mysql, { type Pool, type PoolOptions, type ResultSetHeader } from "mysql2/promise";

export type AppRole = "Security_Analyst" | "Asset_Owner" | "Admin";
/** One pool per database account. The account (not the app) decides what SQL may run. */
export type PoolKey = AppRole | "auth";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Row = Record<string, any>;

const globalForPools = globalThis as unknown as { __zdhMysql?: Partial<Record<PoolKey, Pool>> };

function env(name: string): string {
  const v = process.env[name];
  if (v === undefined || v === "") throw new Error(`Missing environment variable ${name}`);
  return v;
}

function credentials(key: PoolKey): { user: string; password: string } {
  switch (key) {
    case "auth":
      return { user: env("MYSQL_AUTH_USER"), password: env("MYSQL_AUTH_PASSWORD") };
    case "Security_Analyst":
      return { user: env("MYSQL_ANALYST_USER"), password: env("MYSQL_ANALYST_PASSWORD") };
    case "Asset_Owner":
      return { user: env("MYSQL_OWNER_USER"), password: env("MYSQL_OWNER_PASSWORD") };
    case "Admin":
      return { user: env("MYSQL_ADMIN_USER"), password: env("MYSQL_ADMIN_PASSWORD") };
  }
}

export function getPool(key: PoolKey): Pool {
  const pools = (globalForPools.__zdhMysql ??= {});
  let pool = pools[key];
  if (!pool) {
    const { user, password } = credentials(key);
    const options: PoolOptions = {
      host: env("MYSQL_HOST"),
      port: Number(process.env.MYSQL_PORT ?? 3306),
      database: env("MYSQL_DATABASE"),
      user,
      password,
      connectionLimit: 5,
      dateStrings: true, // return DATETIME as plain strings, no time-zone surprises
      decimalNumbers: true, // DECIMAL columns as JS numbers
      namedPlaceholders: false,
    };
    pool = mysql.createPool(options);
    pools[key] = pool;
  }
  return pool;
}

/** Run a parameterised query as the given database account. */
export async function query<T = Row>(key: PoolKey, sql: string, params: unknown[] = []): Promise<T[]> {
  const [rows] = await getPool(key).query(sql, params);
  return rows as T[];
}

/** Run a write statement and return the affected-row information. */
export async function run(key: PoolKey, sql: string, params: unknown[] = []): Promise<ResultSetHeader> {
  const [res] = await getPool(key).query(sql, params);
  return res as ResultSetHeader;
}

/** CALL a stored procedure and return its first result set (or [] if it returns none). */
export async function call<T = Row>(key: PoolKey, name: string, args: unknown[] = []): Promise<T[]> {
  if (!/^[a-z_]+$/i.test(name)) throw new Error("Invalid procedure name");
  const placeholders = args.map(() => "?").join(", ");
  const [result] = await getPool(key).query(`CALL ${name}(${placeholders})`, args);
  if (Array.isArray(result) && Array.isArray(result[0])) return result[0] as T[];
  return [];
}

/** Admin-only: run the SLA sweep (OUT parameter needs one connection for CALL + SELECT). */
export async function runSlaSweep(): Promise<number> {
  const conn = await getPool("Admin").getConnection();
  try {
    await conn.query("CALL sp_sla_sweep(@escalated)");
    const [rows] = await conn.query("SELECT @escalated AS escalated");
    return Number((rows as Row[])[0]?.escalated ?? 0);
  } finally {
    conn.release();
  }
}

export function roleToPoolKey(role: AppRole): PoolKey {
  return role;
}
