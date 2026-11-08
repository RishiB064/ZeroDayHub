// Cross-platform database setup (Windows, macOS, Linux): no bash, mysql or psql needed.
// Creates and seeds BOTH databases from db/mysql/01..07 and db/pg/01..03.
// Credentials come from .env.local. Usage: npm run db:init
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import mysql from "mysql2/promise";
import pg from "pg";

const envFile = resolve(process.env.ENV_FILE ?? ".env.local");
if (!existsSync(envFile)) {
  console.error(`Missing ${envFile}. Copy .env.example to .env.local and fill it in.`);
  process.exit(1);
}
process.loadEnvFile(envFile);
const env = (n, d) => process.env[n] ?? d;

/** Replace __NAME__ tokens with env vars (SQL-escaped); fail if any is missing. */
function render(file) {
  const missing = new Set();
  const out = readFileSync(file, "utf8").replace(/__([A-Z][A-Z0-9_]+)__/g, (_m, name) => {
    const v = process.env[name] ?? (name === "APP_HOST" ? "localhost" : undefined);
    if (v === undefined || v === "") { missing.add(name); return `__${name}__`; }
    return String(v).replace(/\\/g, "\\\\").replace(/'/g, "''");
  });
  if (missing.size) { console.error(`Missing environment variables: ${[...missing].join(", ")}`); process.exit(1); }
  return out;
}

/** Split a MySQL script into statements; understands DELIMITER, quotes and comments. */
function splitMysql(text) {
  const stmts = [];
  let delim = ";", buf = "", i = 0;
  const n = text.length;
  const atLineStart = () => i === 0 || text[i - 1] === "\n";
  while (i < n) {
    const c = text[i];
    if (atLineStart() && /^DELIMITER[ \t]/i.test(text.slice(i, i + 10))) {
      const end = text.indexOf("\n", i);
      const line = text.slice(i, end === -1 ? n : end);
      delim = line.split(/\s+/)[1];
      i = end === -1 ? n : end + 1;
      continue;
    }
    if (c === "-" && text[i + 1] === "-" && /\s/.test(text[i + 2] ?? " ")) { while (i < n && text[i] !== "\n") i++; continue; }
    if (c === "#") { while (i < n && text[i] !== "\n") i++; continue; }
    if (c === "/" && text[i + 1] === "*") { const e = text.indexOf("*/", i + 2); i = e === -1 ? n : e + 2; continue; }
    if (c === "'" || c === '"' || c === "`") {
      let j = i + 1;
      while (j < n) {
        if (text[j] === "\\" && c !== "`") { j += 2; continue; }
        if (text[j] === c) { if (text[j + 1] === c) { j += 2; continue; } break; }
        j++;
      }
      buf += text.slice(i, j + 1); i = j + 1; continue;
    }
    if (text.startsWith(delim, i)) {
      if (buf.trim()) stmts.push(buf.trim());
      buf = ""; i += delim.length; continue;
    }
    buf += c; i++;
  }
  if (buf.trim()) stmts.push(buf.trim());
  return stmts;
}

async function runMysql(conn, label, sql) {
  console.log(`  applying ${label}`);
  for (const s of splitMysql(sql)) {
    try { await conn.query(s); }
    catch (e) { console.error(`\nFailed in ${label}:\n${s.slice(0, 300)}\n-> ${e.message}`); throw e; }
  }
}

async function main() {
  console.log("== MySQL ==========================================================");
  const conn = await mysql.createConnection({
    host: env("MYSQL_SETUP_HOST", env("MYSQL_HOST", "localhost")),
    port: Number(env("MYSQL_SETUP_PORT", env("MYSQL_PORT", "3306"))),
    user: env("MYSQL_SETUP_USER"), password: env("MYSQL_SETUP_PASSWORD", ""),
    charset: "utf8mb4", multipleStatements: false,
  });
  for (const f of ["01_schema", "02_functions", "03_views", "04_procedures", "05_triggers_events"]) {
    await runMysql(conn, `db/mysql/${f}.sql`, readFileSync(`db/mysql/${f}.sql`, "utf8"));
  }
  await runMysql(conn, "db/mysql/06_roles.sql.tpl", render("db/mysql/06_roles.sql.tpl"));
  await runMysql(conn, "db/mysql/07_seed.sql", readFileSync("db/mysql/07_seed.sql", "utf8"));
  await conn.end();

  console.log("== PostgreSQL + pgvector ==========================================");
  const base = {
    host: env("PG_SETUP_HOST", env("PG_HOST", "localhost")),
    port: Number(env("PG_SETUP_PORT", env("PG_PORT", "5432"))),
    user: env("PG_SETUP_USER"), password: env("PG_SETUP_PASSWORD", ""),
  };
  const dbName = env("PG_DATABASE", "zerodayhub_vectors");
  const admin = new pg.Client({ ...base, database: "postgres" });
  await admin.connect();
  const exists = await admin.query("SELECT 1 FROM pg_database WHERE datname = $1", [dbName]);
  if (!exists.rowCount) { console.log(`  creating database ${dbName}`); await admin.query(`CREATE DATABASE "${dbName}"`); }
  await admin.end();

  const db = new pg.Client({ ...base, database: dbName });
  await db.connect();
  db.on("notice", () => {});
  for (const [label, sql] of [
    ["db/pg/01_schema.sql", readFileSync("db/pg/01_schema.sql", "utf8")],
    ["db/pg/02_functions_views.sql", readFileSync("db/pg/02_functions_views.sql", "utf8")],
    ["db/pg/03_roles.sql.tpl", render("db/pg/03_roles.sql.tpl")],
  ]) {
    console.log(`  applying ${label}`);
    await db.query(sql);
  }
  await db.end();
  console.log("\nDone. Next:  npm run db:seed-vectors   (embeds advisories into PostgreSQL)");
}

main().catch((e) => { console.error("\nSetup failed:", e.message); process.exit(1); });
