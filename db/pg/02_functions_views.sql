-- =====================================================================
-- File 02 - retrieval functions and statistics view
-- Rubric: Vector similarity search, full-text search, retrieval strategy
-- =====================================================================

-- Similarity metric: cosine distance (<=>).  similarity = 1 - distance, so
-- 1.0 means identical direction and 0.0 means unrelated.  Rows are only
-- compared with vectors produced by the SAME model.  Optional metadata filters.
DROP FUNCTION IF EXISTS fn_semantic_search(vector, text, int, text, numeric, text);
CREATE FUNCTION fn_semantic_search(
    q            vector(384),
    p_model      text,
    p_limit      int      DEFAULT 5,
    p_severity   text     DEFAULT NULL,
    p_min_cvss   numeric  DEFAULT NULL,
    p_cwe        text     DEFAULT NULL
)
RETURNS TABLE (
    cve_id               varchar,
    similarity           double precision,
    advisory_text        text,
    exploit_summary      text,
    remediation_playbook text,
    metadata             jsonb
)
LANGUAGE sql STABLE AS $$
    SELECT v.cve_id,
           1 - (v.embedding <=> q) AS similarity,
           v.advisory_text, v.exploit_summary, v.remediation_playbook, v.metadata
    FROM cve_threat_vectors v
    WHERE v.embedding_model = p_model
      AND (p_severity IS NULL OR v.metadata->>'severity' = p_severity)
      AND (p_min_cvss IS NULL OR (v.metadata->>'cvss')::numeric >= p_min_cvss)
      AND (p_cwe      IS NULL OR v.metadata->>'cwe' = p_cwe)
    ORDER BY v.embedding <=> q
    LIMIT greatest(p_limit, 1);
$$;

-- Hybrid retrieval: Reciprocal Rank Fusion of the semantic ranking and the
-- full-text ranking (score = sum of 1/(60+rank)).  Finds exact identifiers
-- and rare keywords that pure vector search can miss.
DROP FUNCTION IF EXISTS fn_hybrid_search(vector, text, text, int);
CREATE FUNCTION fn_hybrid_search(
    q        vector(384),
    p_text   text,
    p_model  text,
    p_limit  int DEFAULT 5
)
RETURNS TABLE (
    cve_id               varchar,
    score                double precision,
    similarity           double precision,
    advisory_text        text,
    exploit_summary      text,
    remediation_playbook text,
    metadata             jsonb
)
LANGUAGE sql STABLE AS $$
    WITH sem AS (
        SELECT v.cve_id, row_number() OVER (ORDER BY v.embedding <=> q) AS rnk
        FROM cve_threat_vectors v
        WHERE v.embedding_model = p_model
        ORDER BY v.embedding <=> q
        LIMIT 30
    ),
    kw AS (
        SELECT v.cve_id,
               row_number() OVER (ORDER BY ts_rank(v.search_tsv, websearch_to_tsquery('english', p_text)) DESC) AS rnk
        FROM cve_threat_vectors v
        WHERE v.search_tsv @@ websearch_to_tsquery('english', p_text)
        ORDER BY ts_rank(v.search_tsv, websearch_to_tsquery('english', p_text)) DESC
        LIMIT 30
    ),
    fused AS (
        SELECT coalesce(sem.cve_id, kw.cve_id) AS cve_id,
               coalesce(1.0 / (60 + sem.rnk), 0) + coalesce(1.0 / (60 + kw.rnk), 0) AS score
        FROM sem FULL OUTER JOIN kw ON kw.cve_id = sem.cve_id
    )
    SELECT f.cve_id, f.score::double precision,
           1 - (v.embedding <=> q) AS similarity,
           v.advisory_text, v.exploit_summary, v.remediation_playbook, v.metadata
    FROM fused f
    JOIN cve_threat_vectors v ON v.cve_id = f.cve_id
    ORDER BY f.score DESC
    LIMIT greatest(p_limit, 1);
$$;

-- Statistics for the dashboard / documentation
CREATE OR REPLACE VIEW v_vector_stats AS
SELECT embedding_model,
       count(*)                                  AS vectors,
       count(DISTINCT metadata->>'cwe')          AS distinct_cwes,
       min(created_at)                           AS first_indexed,
       max(updated_at)                           AS last_updated
FROM cve_threat_vectors
GROUP BY embedding_model;
