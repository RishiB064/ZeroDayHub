-- =====================================================================
-- File 03 - PostgreSQL roles (database-level RBAC for the vector store)
-- TEMPLATE: scripts/init-db.sh substitutes the double-underscore tokens
-- from .env.local, so passwords are never stored in the repository.
--
--   zdh_vec_reader  SELECT + search functions   (Asset_Owner sessions)
--   zdh_vec_writer  SELECT/INSERT/UPDATE/DELETE (Security_Analyst, Admin sessions)
-- =====================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zdh_vec_reader') THEN
        CREATE ROLE zdh_vec_reader LOGIN PASSWORD '__PG_READER_PASSWORD__';
    ELSE
        ALTER ROLE zdh_vec_reader LOGIN PASSWORD '__PG_READER_PASSWORD__';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zdh_vec_writer') THEN
        CREATE ROLE zdh_vec_writer LOGIN PASSWORD '__PG_WRITER_PASSWORD__';
    ELSE
        ALTER ROLE zdh_vec_writer LOGIN PASSWORD '__PG_WRITER_PASSWORD__';
    END IF;
END
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
-- functions (including the pgvector operators) keep PUBLIC execute; this also heals earlier revokes
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO PUBLIC;

GRANT CONNECT ON DATABASE __PG_DATABASE__ TO zdh_vec_reader, zdh_vec_writer;
GRANT USAGE   ON SCHEMA public           TO zdh_vec_reader, zdh_vec_writer;

GRANT SELECT ON cve_threat_vectors, v_vector_stats TO zdh_vec_reader;
GRANT SELECT, INSERT, UPDATE, DELETE ON cve_threat_vectors TO zdh_vec_writer;
GRANT SELECT ON v_vector_stats TO zdh_vec_writer;

GRANT EXECUTE ON FUNCTION fn_semantic_search(vector, text, int, text, numeric, text)
    TO zdh_vec_reader, zdh_vec_writer;
GRANT EXECUTE ON FUNCTION fn_hybrid_search(vector, text, text, int)
    TO zdh_vec_reader, zdh_vec_writer;
