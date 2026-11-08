-- =====================================================================
-- ZeroDayHub :: PostgreSQL 16 + pgvector  (semantic threat-intel store)
-- File 01 - extension, table, constraints, indexes, triggers
-- Rubric: NoSQL/Vector database creation, technology justification
--
-- DATA MODEL
--   One row per CVE advisory ("document"), linked to MySQL cve_records
--   by cve_id (logical reference - two engines cannot share a FK).
--     advisory_text / exploit_summary / remediation_playbook  unstructured text
--     metadata JSONB   flexible attributes: severity, cvss, cwe, vendor, product, tags
--     embedding        vector(384): dense embedding of the combined text
--     embedding_model  which model produced the vector (vectors from different
--                      models live in different spaces and must never be compared)
--     content_hash     SHA-256 of the embedded text, so unchanged text is never re-embedded
--     search_tsv       generated tsvector for keyword (full-text) search
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS vector;

DROP TABLE IF EXISTS cve_threat_vectors CASCADE;

CREATE TABLE cve_threat_vectors (
    cve_id               VARCHAR(25)  PRIMARY KEY,
    advisory_text        TEXT         NOT NULL,
    exploit_summary      TEXT,
    remediation_playbook TEXT,
    metadata             JSONB        NOT NULL DEFAULT '{}'::jsonb,
    embedding            vector(384)  NOT NULL,
    embedding_model      VARCHAR(80)  NOT NULL,
    content_hash         CHAR(64)     NOT NULL,
    search_tsv           tsvector GENERATED ALWAYS AS (
        to_tsvector('english',
            coalesce(advisory_text, '') || ' ' ||
            coalesce(exploit_summary, '') || ' ' ||
            coalesce(remediation_playbook, ''))
    ) STORED,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT chk_ctv_cve_id   CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    CONSTRAINT chk_ctv_text     CHECK (char_length(btrim(advisory_text)) >= 20),
    CONSTRAINT chk_ctv_metadata CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT chk_ctv_hash     CHECK (content_hash ~ '^[0-9a-f]{64}$')
);

COMMENT ON TABLE  cve_threat_vectors IS 'Unstructured advisory text + embeddings for semantic CVE search';
COMMENT ON COLUMN cve_threat_vectors.embedding IS '384-dim L2-normalised embedding; compared with cosine distance (<=>)';

-- Approximate nearest-neighbour index: HNSW with cosine operator class.
--   m = 16              max connections per graph node
--   ef_construction = 64 candidate list size while building
CREATE INDEX idx_ctv_embedding_hnsw
    ON cve_threat_vectors USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- Metadata filtering: containment queries (metadata @> '{"severity":"Critical"}')
CREATE INDEX idx_ctv_metadata_gin ON cve_threat_vectors USING gin (metadata jsonb_path_ops);
-- Keyword search
CREATE INDEX idx_ctv_tsv_gin      ON cve_threat_vectors USING gin (search_tsv);
-- Model partitioning of the vector space
CREATE INDEX idx_ctv_model        ON cve_threat_vectors (embedding_model);
-- Common filter expression
CREATE INDEX idx_ctv_severity     ON cve_threat_vectors ((metadata->>'severity'));

-- keep updated_at honest
CREATE OR REPLACE FUNCTION fn_ctv_touch() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_ctv_touch
BEFORE UPDATE ON cve_threat_vectors
FOR EACH ROW EXECUTE FUNCTION fn_ctv_touch();
