/**
 * Copies the advisory text in db/seed/advisories.json into PostgreSQL (pgvector):
 * generates one embedding per CVE and marks the MySQL row SYNCED.
 * Usage: npm run db:seed-vectors      (reads .env.local)
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const envFile = resolve(process.cwd(), process.env.ENV_FILE ?? ".env.local");
process.loadEnvFile(envFile);

async function main() {
  const { query } = await import("../src/lib/db/mysql");
  const { buildEmbeddingText, embeddingModelName, embeddingProvider } = await import("../src/lib/embedding");
  const { upsertVector, vectorStats } = await import("../src/lib/services/vectors");
  const { getPool } = await import("../src/lib/db/mysql");
  const { getPgPool } = await import("../src/lib/db/pg");

  interface Advisory {
    cve_id: string; vendor: string; product: string; tags: string[];
    advisory_text: string; exploit_summary: string; remediation_playbook: string;
  }
  const advisories: Advisory[] = JSON.parse(readFileSync(resolve("db/seed/advisories.json"), "utf8"));

  console.log(`Embedding provider: ${embeddingProvider()}  model: ${embeddingModelName()}`);
  let done = 0;
  for (const a of advisories) {
    const rows = await query(
      "Admin",
      `SELECT c.title, c.cvss_score, c.severity, c.cwe_id, w.name AS cwe_name
         FROM cve_records c JOIN cwe_catalog w ON w.cwe_id = c.cwe_id WHERE c.cve_id = ?`,
      [a.cve_id],
    );
    const c = rows[0];
    if (!c) { console.warn(`  skip ${a.cve_id}: not in MySQL`); continue; }
    const action = await upsertVector({
      cveId: a.cve_id,
      advisoryText: a.advisory_text,
      exploitSummary: a.exploit_summary,
      remediationPlaybook: a.remediation_playbook,
      embeddingText: buildEmbeddingText({
        title: c.title, cweName: c.cwe_name, advisoryText: a.advisory_text, exploitSummary: a.exploit_summary,
      }),
      metadata: {
        severity: c.severity, cvss: Number(c.cvss_score), cwe: c.cwe_id, cweName: c.cwe_name,
        vendor: a.vendor, product: a.product, tags: a.tags,
      },
    });
    await query("Admin", "UPDATE cve_records SET vector_sync_status = 'SYNCED' WHERE cve_id = ?", [a.cve_id]);
    done += 1;
    console.log(`  ${a.cve_id}  ${action}`);
  }
  console.log(`Seeded ${done} advisories.`, await vectorStats("Admin"));
  await getPool("Admin").end();
  await getPgPool("writer").end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
