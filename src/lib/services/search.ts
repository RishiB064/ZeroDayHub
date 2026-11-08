import { query, type Row } from "../db/mysql";
import { embedText, embeddingModelName } from "../embedding";
import type { SessionUser } from "../session";
import { countVectors, searchVectors, vectorStats, type VectorMetadata } from "./vectors";
import { z } from "zod";
import { searchSchema } from "../validation";

export type SearchInput = z.infer<typeof searchSchema>;

export interface SearchResult {
  cveId: string;
  similarity: number;
  score?: number;
  title: string;
  cweId: string;
  cweName: string;
  cvssScore: number;
  severity: string;
  openTickets: number | null;
  affectedAssets: number | null;
  advisoryText: string;
  exploitSummary: string | null;
  remediationPlaybook: string | null;
  tags: string[];
  vendor?: string;
  product?: string;
}

export interface SearchResponse {
  results: SearchResult[];
  model: string;
  mode: string;
  note?: string;
}

/**
 * Retrieval strategy:
 *   1. embed the analyst's free-text description with the same model used at index time
 *   2. PostgreSQL ranks by cosine distance over the HNSW index (optionally fused with
 *      full-text ranking in hybrid mode) and applies metadata filters
 *   3. the winners are enriched with live structured data from MySQL
 *      (title, CVSS, open tickets) so the answer is actionable
 */
export async function searchThreats(user: SessionUser, input: SearchInput): Promise<SearchResponse> {
  const model = embeddingModelName();
  const queryVector = await embedText(input.query);
  const hits = await searchVectors(user.role, {
    queryVector, queryText: input.query, k: input.k, mode: input.mode,
    severity: input.severity, minCvss: input.minCvss, cwe: input.cwe,
  });

  let note: string | undefined;
  if (hits.length === 0) {
    const stats = await vectorStats(user.role).catch(() => []);
    const total = await countVectors(user.role).catch(() => 0);
    if (total === 0) note = "The vector store is empty. Run `npm run db:seed-vectors` or add CVEs with advisory text.";
    else if (!stats.some((s) => s.embedding_model === model)) {
      note = `Stored vectors were created with a different model (${stats.map((s) => s.embedding_model).join(", ")}) than the current one (${model}). Re-sync the catalogue on the CVEs page.`;
    }
    return { results: [], model, mode: input.mode, note };
  }

  const ids = hits.map((h) => h.cve_id);
  let rows: Row[];
  if (user.role === "Asset_Owner") {
    rows = await query(
      user.role,
      `SELECT c.cve_id, c.title, c.cwe_id, w.name AS cwe_name, c.cvss_score, c.severity,
              NULL AS open_tickets, NULL AS affected_assets
         FROM cve_records c JOIN cwe_catalog w ON w.cwe_id = c.cwe_id
        WHERE c.cve_id IN (?) AND c.is_retired = FALSE`,
      [ids],
    );
  } else {
    rows = await query(
      user.role,
      "SELECT cve_id, title, cwe_id, cwe_name, cvss_score, severity, open_tickets, affected_assets FROM v_cve_catalog WHERE cve_id IN (?) AND is_retired = FALSE",
      [ids],
    );
  }
  const byId = new Map(rows.map((r) => [String(r.cve_id), r]));

  const results: SearchResult[] = hits.flatMap((h) => {
    const r = byId.get(h.cve_id);
    if (!r) return []; // vector exists but the CVE is gone/retired in MySQL: hide the orphan
    const meta = h.metadata as VectorMetadata;
    return [{
      cveId: h.cve_id,
      similarity: Number(h.similarity),
      score: h.score !== undefined ? Number(h.score) : undefined,
      title: String(r.title),
      cweId: String(r.cwe_id),
      cweName: String(r.cwe_name),
      cvssScore: Number(r.cvss_score),
      severity: String(r.severity),
      openTickets: r.open_tickets === null ? null : Number(r.open_tickets),
      affectedAssets: r.affected_assets === null ? null : Number(r.affected_assets),
      advisoryText: h.advisory_text,
      exploitSummary: h.exploit_summary,
      remediationPlaybook: h.remediation_playbook,
      tags: Array.isArray(meta.tags) ? meta.tags : [],
      vendor: typeof meta.vendor === "string" ? meta.vendor : undefined,
      product: typeof meta.product === "string" ? meta.product : undefined,
    }];
  });
  return { results, model, mode: input.mode, note };
}
