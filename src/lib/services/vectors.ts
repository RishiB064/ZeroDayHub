import { getPgPool, pgKeyForRole, toVectorLiteral } from "../db/pg";
import type { AppRole, Row } from "../db/mysql";
import { embedText, embeddingModelName, sha256 } from "../embedding";

/**
 * Vector store operations on PostgreSQL + pgvector (rubric: NoSQL/Vector RUD).
 *   CREATE  upsertVector (insert)         READ    searchVectors / getVectorDoc
 *   UPDATE  upsertVector (update)         DELETE  deleteVector
 */
export interface VectorMetadata {
  severity: string;
  cvss: number;
  cwe: string;
  cweName?: string;
  vendor?: string;
  product?: string;
  tags?: string[];
  [k: string]: unknown;
}

export interface VectorInput {
  cveId: string;
  advisoryText: string;
  exploitSummary?: string | null;
  remediationPlaybook?: string | null;
  metadata: VectorMetadata;
  /** the exact text that gets embedded (see buildEmbeddingText) */
  embeddingText: string;
}

export type UpsertAction = "inserted" | "re-embedded" | "metadata-only";

/** CREATE or UPDATE. Re-embeds only when the embedded text or the model changed. */
export async function upsertVector(input: VectorInput): Promise<UpsertAction> {
  const pool = getPgPool("writer");
  const model = embeddingModelName();
  const hash = sha256(input.embeddingText);

  const existing = await pool.query(
    "SELECT content_hash, embedding_model FROM cve_threat_vectors WHERE cve_id = $1",
    [input.cveId],
  );
  const row = existing.rows[0] as { content_hash: string; embedding_model: string } | undefined;

  if (row && row.content_hash === hash && row.embedding_model === model) {
    // text unchanged: skip the (expensive) embedding, refresh the other columns
    await pool.query(
      `UPDATE cve_threat_vectors
          SET advisory_text = $2, exploit_summary = $3, remediation_playbook = $4, metadata = $5::jsonb
        WHERE cve_id = $1`,
      [input.cveId, input.advisoryText, input.exploitSummary ?? null, input.remediationPlaybook ?? null,
       JSON.stringify(input.metadata)],
    );
    return "metadata-only";
  }

  const vector = await embedText(input.embeddingText);
  await pool.query(
    `INSERT INTO cve_threat_vectors
        (cve_id, advisory_text, exploit_summary, remediation_playbook, metadata,
         embedding, embedding_model, content_hash)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6::vector, $7, $8)
     ON CONFLICT (cve_id) DO UPDATE SET
        advisory_text        = EXCLUDED.advisory_text,
        exploit_summary      = EXCLUDED.exploit_summary,
        remediation_playbook = EXCLUDED.remediation_playbook,
        metadata             = EXCLUDED.metadata,
        embedding            = EXCLUDED.embedding,
        embedding_model      = EXCLUDED.embedding_model,
        content_hash         = EXCLUDED.content_hash`,
    [input.cveId, input.advisoryText, input.exploitSummary ?? null, input.remediationPlaybook ?? null,
     JSON.stringify(input.metadata), toVectorLiteral(vector), model, hash],
  );
  return row ? "re-embedded" : "inserted";
}

/** DELETE */
export async function deleteVector(cveId: string): Promise<boolean> {
  const res = await getPgPool("writer").query("DELETE FROM cve_threat_vectors WHERE cve_id = $1", [cveId]);
  return (res.rowCount ?? 0) > 0;
}

export interface VectorDoc {
  cve_id: string;
  advisory_text: string;
  exploit_summary: string | null;
  remediation_playbook: string | null;
  metadata: VectorMetadata;
  embedding_model: string;
  updated_at: string;
}

/** READ one document (without the 384 numbers) */
export async function getVectorDoc(role: AppRole, cveId: string): Promise<VectorDoc | null> {
  const res = await getPgPool(pgKeyForRole(role)).query(
    `SELECT cve_id, advisory_text, exploit_summary, remediation_playbook, metadata,
            embedding_model, updated_at::text AS updated_at
       FROM cve_threat_vectors WHERE cve_id = $1`,
    [cveId],
  );
  return (res.rows[0] as VectorDoc | undefined) ?? null;
}

export async function listVectorIds(): Promise<string[]> {
  const res = await getPgPool("writer").query("SELECT cve_id FROM cve_threat_vectors");
  return res.rows.map((r: { cve_id: string }) => r.cve_id);
}

export interface SearchFilters {
  severity?: string;
  minCvss?: number;
  cwe?: string;
}

export interface VectorHit {
  cve_id: string;
  similarity: number;
  score?: number;
  advisory_text: string;
  exploit_summary: string | null;
  remediation_playbook: string | null;
  metadata: VectorMetadata;
}

/** READ: similarity search. `semantic` = cosine distance; `hybrid` = cosine + full-text fused with RRF. */
export async function searchVectors(
  role: AppRole,
  opts: { queryVector: number[]; queryText: string; k: number; mode: "semantic" | "hybrid" } & SearchFilters,
): Promise<VectorHit[]> {
  const pool = getPgPool(pgKeyForRole(role));
  const model = embeddingModelName();
  const vec = toVectorLiteral(opts.queryVector);

  if (opts.mode === "hybrid") {
    const res = await pool.query(
      "SELECT * FROM fn_hybrid_search($1::vector, $2::text, $3::text, $4::int)",
      [vec, opts.queryText, model, opts.k * 3],
    );
    // the hybrid function has no metadata filters: apply them to the fused list
    return (res.rows as VectorHit[])
      .filter((h) => !opts.severity || h.metadata.severity === opts.severity)
      .filter((h) => opts.minCvss === undefined || Number(h.metadata.cvss) >= opts.minCvss)
      .filter((h) => !opts.cwe || h.metadata.cwe === opts.cwe)
      .slice(0, opts.k);
  }

  const res = await pool.query(
    "SELECT * FROM fn_semantic_search($1::vector, $2::text, $3::int, $4::text, $5::numeric, $6::text)",
    [vec, model, opts.k, opts.severity ?? null, opts.minCvss ?? null, opts.cwe ?? null],
  );
  return res.rows as VectorHit[];
}

export interface VectorStat extends Row {
  embedding_model: string;
  vectors: number;
  distinct_cwes: number;
}

export async function vectorStats(role: AppRole): Promise<VectorStat[]> {
  const res = await getPgPool(pgKeyForRole(role)).query(
    "SELECT embedding_model, vectors::int AS vectors, distinct_cwes::int AS distinct_cwes, last_updated::text FROM v_vector_stats ORDER BY vectors DESC",
  );
  return res.rows as VectorStat[];
}

export async function countVectors(role: AppRole): Promise<number> {
  const res = await getPgPool(pgKeyForRole(role)).query("SELECT count(*)::int AS n FROM cve_threat_vectors");
  return res.rows[0].n as number;
}
