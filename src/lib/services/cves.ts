import { query, run, type AppRole, type Row } from "../db/mysql";
import { buildEmbeddingText } from "../embedding";
import { ApiError } from "../errors";
import type { SessionUser } from "../session";
import { deleteVector, getVectorDoc, listVectorIds, upsertVector, type VectorDoc } from "./vectors";
import { z } from "zod";
import { cveCreateSchema, cveWriteSchema } from "../validation";

export type CveWrite = z.infer<typeof cveWriteSchema>;
export type CveCreate = z.infer<typeof cveCreateSchema>;

export interface CveFilters {
  q?: string;
  severity?: string;
  sync?: string;
  includeRetired?: boolean;
}

/** List the catalogue. Analysts/admins get live ticket counts; owners get reference data only. */
export async function listCves(user: SessionUser, f: CveFilters = {}): Promise<Row[]> {
  const where: string[] = [];
  const params: unknown[] = [];
  if (!f.includeRetired) where.push("c.is_retired = FALSE");
  if (f.severity) { where.push("c.severity = ?"); params.push(f.severity); }
  if (f.sync) { where.push("c.vector_sync_status = ?"); params.push(f.sync); }
  if (f.q && f.q.trim()) {
    // MySQL FULLTEXT (word match, relevance) OR substring fallback for partial words / ids
    where.push("(MATCH(c.title) AGAINST (? IN NATURAL LANGUAGE MODE) OR c.title LIKE ? OR c.cve_id LIKE ?)");
    const q = f.q.trim();
    params.push(q, `%${q}%`, `%${q}%`);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";

  if (user.role === "Asset_Owner") {
    return query(
      user.role,
      `SELECT c.cve_id, c.title, c.cwe_id, w.name AS cwe_name, c.cvss_score, c.severity, c.published_date,
              c.vector_sync_status, c.is_retired, NULL AS open_tickets, NULL AS affected_assets
         FROM cve_records c JOIN cwe_catalog w ON w.cwe_id = c.cwe_id
         ${clause} ORDER BY c.cvss_score DESC, c.cve_id`,
      params,
    );
  }
  return query(
    user.role,
    `SELECT v.* FROM v_cve_catalog v JOIN cve_records c ON c.cve_id = v.cve_id
       ${clause} ORDER BY v.cvss_score DESC, v.cve_id`,
    params,
  );
}

export interface CveDetail {
  record: Row;
  vector: VectorDoc | null;
}

export async function getCve(user: SessionUser, cveId: string): Promise<CveDetail | null> {
  const rows = await query(
    user.role,
    `SELECT c.cve_id, c.title, c.cwe_id, w.name AS cwe_name, c.cvss_score, c.severity,
            c.published_date, c.vector_sync_status, c.is_retired
       FROM cve_records c JOIN cwe_catalog w ON w.cwe_id = c.cwe_id WHERE c.cve_id = ?`,
    [cveId],
  );
  if (!rows[0]) return null;
  return { record: rows[0], vector: await getVectorDoc(user.role, cveId) };
}

async function setSync(role: AppRole, cveId: string, status: "SYNCED" | "FAILED" | "PENDING") {
  await query(role, "UPDATE cve_records SET vector_sync_status = ? WHERE cve_id = ?", [status, cveId]);
}

interface SyncOutcome {
  status: "SYNCED" | "FAILED";
  action?: string;
  warning?: string;
}

/** Copy the CVE into PostgreSQL (create/update) and record the outcome in MySQL. */
async function syncToVectorStore(role: AppRole, cveId: string, doc: CveWrite): Promise<SyncOutcome> {
  try {
    const meta = await query(
      role,
      `SELECT c.severity, c.cvss_score, c.cwe_id, w.name AS cwe_name
         FROM cve_records c JOIN cwe_catalog w ON w.cwe_id = c.cwe_id WHERE c.cve_id = ?`,
      [cveId],
    );
    const m = meta[0];
    if (!m) throw new ApiError(404, "CVE not found");
    const action = await upsertVector({
      cveId,
      advisoryText: doc.advisoryText,
      exploitSummary: doc.exploitSummary || null,
      remediationPlaybook: doc.remediationPlaybook || null,
      embeddingText: buildEmbeddingText({
        title: doc.title, cweName: m.cwe_name, advisoryText: doc.advisoryText, exploitSummary: doc.exploitSummary,
      }),
      metadata: {
        severity: m.severity, cvss: Number(m.cvss_score), cwe: m.cwe_id, cweName: m.cwe_name,
        vendor: doc.vendor || undefined, product: doc.product || undefined, tags: doc.tags ?? [],
      },
    });
    await setSync(role, cveId, "SYNCED");
    return { status: "SYNCED", action };
  } catch (err) {
    await setSync(role, cveId, "FAILED").catch(() => undefined);
    return { status: "FAILED", warning: err instanceof Error ? err.message : "vector sync failed" };
  }
}

/** CREATE: MySQL first (source of truth), then the vector copy. */
export async function createCve(user: SessionUser, input: CveCreate) {
  await query(
    user.role,
    "INSERT INTO cve_records (cve_id, title, cwe_id, cvss_score, published_date) VALUES (?, ?, ?, ?, ?)",
    [input.cveId, input.title, input.cweId, input.cvssScore, input.publishedDate],
  );
  const sync = await syncToVectorStore(user.role, input.cveId, input);
  return { cveId: input.cveId, sync };
}

/** UPDATE: structured fields in MySQL, text + embedding in PostgreSQL. */
export async function updateCve(user: SessionUser, cveId: string, input: CveWrite) {
  const res = await run(
    user.role,
    `UPDATE cve_records SET title = ?, cwe_id = ?, cvss_score = ?, published_date = ?,
            vector_sync_status = 'PENDING' WHERE cve_id = ? AND is_retired = FALSE`,
    [input.title, input.cweId, input.cvssScore, input.publishedDate, cveId],
  );
  if (!res.affectedRows) {
    throw new ApiError(404, "CVE not found or retired");
  }
  const sync = await syncToVectorStore(user.role, cveId, input);
  return { cveId, sync };
}

/**
 * DELETE: a CVE that still has tickets is RETIRED (kept for audit history, vector removed);
 * a CVE with no tickets is deleted from both databases.
 */
export async function removeCve(user: SessionUser, cveId: string) {
  const used = await query<{ n: number }>(user.role, "SELECT COUNT(*) AS n FROM vuln_tickets WHERE cve_id = ?", [cveId]);
  const hasTickets = Number(used[0]?.n ?? 0) > 0;
  if (hasTickets) {
    await query(user.role, "UPDATE cve_records SET is_retired = TRUE, vector_sync_status = 'SYNCED' WHERE cve_id = ?", [cveId]);
  } else {
    await query(user.role, "DELETE FROM cve_records WHERE cve_id = ?", [cveId]);
  }
  const vectorDeleted = await deleteVector(cveId).catch(() => false);
  return { cveId, mode: hasTickets ? "retired" : "deleted", vectorDeleted };
}

/** Re-sync a single CVE from the text already stored in PostgreSQL (e.g. after switching model). */
export async function resyncCve(user: SessionUser, cveId: string) {
  const detail = await getCve(user, cveId);
  if (!detail) throw new ApiError(404, "CVE not found");
  if (!detail.vector) {
    throw new ApiError(409, "No advisory text exists for this CVE yet. Edit the CVE and add the advisory text.");
  }
  const v = detail.vector;
  return syncToVectorStore(user.role, cveId, {
    title: String(detail.record.title),
    cweId: String(detail.record.cwe_id),
    cvssScore: Number(detail.record.cvss_score),
    publishedDate: String(detail.record.published_date),
    advisoryText: v.advisory_text,
    exploitSummary: v.exploit_summary ?? "",
    remediationPlaybook: v.remediation_playbook ?? "",
    vendor: String(v.metadata.vendor ?? ""),
    product: String(v.metadata.product ?? ""),
    tags: (v.metadata.tags as string[] | undefined) ?? [],
  });
}

/**
 * Reconciliation between the two engines (they cannot share a transaction):
 *  - retry every CVE whose sync is PENDING/FAILED (when advisory text exists)
 *  - delete vectors whose CVE no longer exists or is retired in MySQL
 */
export async function reconcile(user: SessionUser) {
  const pending = await query<{ cve_id: string }>(
    user.role, "SELECT cve_id FROM cve_records WHERE vector_sync_status <> 'SYNCED' AND is_retired = FALSE",
  );
  let synced = 0, failed = 0, skipped = 0;
  for (const p of pending) {
    try {
      const r = await resyncCve(user, p.cve_id);
      if (r.status === "SYNCED") synced += 1; else failed += 1;
    } catch {
      skipped += 1; // no advisory text yet
    }
  }
  const live = new Set(
    (await query<{ cve_id: string }>(user.role, "SELECT cve_id FROM cve_records WHERE is_retired = FALSE")).map((r) => r.cve_id),
  );
  let orphansRemoved = 0;
  for (const id of await listVectorIds()) {
    if (!live.has(id)) { if (await deleteVector(id)) orphansRemoved += 1; }
  }
  return { synced, failed, skipped, orphansRemoved };
}

export async function listCwes(role: AppRole): Promise<Row[]> {
  return query(role, "SELECT cwe_id, name FROM cwe_catalog ORDER BY CAST(SUBSTRING(cwe_id, 5) AS UNSIGNED)");
}
