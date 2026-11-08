-- =====================================================================
-- File 03 - Views (reporting layer + least-privilege read surfaces)
-- Rubric: Views, CTE, window functions
-- Run after 02_functions.sql.
-- =====================================================================
USE zerodayhub_db;

-- Ticket board: one denormalised row per ticket for dashboards / lists
CREATE OR REPLACE VIEW v_ticket_board AS
SELECT
    t.ticket_id,
    t.asset_id,
    a.hostname,
    a.environment,
    a.criticality,
    a.owner_id,
    ou.full_name                                   AS owner_name,
    d.name                                         AS department,
    t.cve_id,
    c.title                                        AS cve_title,
    c.cvss_score,
    c.severity,
    t.status,
    t.sla_deadline,
    fn_is_sla_breached(t.sla_deadline, t.status)   AS sla_breached,
    TIMESTAMPDIFF(HOUR, NOW(), t.sla_deadline)     AS hours_to_sla,
    fn_risk_index(c.cvss_score, a.criticality)     AS risk_index,
    t.assigned_analyst_id,
    an.full_name                                   AS analyst_name,
    t.remediation_commit_hash,
    t.resolved_at,
    t.created_at
FROM vuln_tickets t
JOIN assets       a  ON a.asset_id      = t.asset_id
JOIN users        ou ON ou.user_id      = a.owner_id
JOIN departments  d  ON d.department_id = ou.department_id
JOIN cve_records  c  ON c.cve_id        = t.cve_id
JOIN users        an ON an.user_id      = t.assigned_analyst_id;

-- Department risk ranking: CTE + aggregate + DENSE_RANK() window function
CREATE OR REPLACE VIEW v_department_risk AS
WITH dept_stats AS (
    SELECT
        d.department_id,
        d.name                                              AS department,
        COUNT(t.ticket_id)                                  AS open_tickets,
        COALESCE(ROUND(AVG(c.cvss_score), 2), 0)            AS avg_cvss,
        COALESCE(SUM(fn_risk_index(c.cvss_score, a.criticality)), 0) AS total_risk,
        COALESCE(SUM(fn_is_sla_breached(t.sla_deadline, t.status)), 0) AS breached_tickets
    FROM departments d
    LEFT JOIN users        u ON u.department_id = d.department_id
    LEFT JOIN assets       a ON a.owner_id      = u.user_id
    LEFT JOIN vuln_tickets t ON t.asset_id      = a.asset_id AND t.status <> 'RESOLVED'
    LEFT JOIN cve_records  c ON c.cve_id        = t.cve_id
    GROUP BY d.department_id, d.name
)
SELECT
    department,
    open_tickets,
    avg_cvss,
    total_risk,
    breached_tickets,
    DENSE_RANK() OVER (ORDER BY total_risk DESC) AS risk_rank
FROM dept_stats;

-- Asset exposure ranked inside each environment tier (window function with PARTITION BY)
CREATE OR REPLACE VIEW v_asset_exposure AS
SELECT
    a.asset_id,
    a.hostname,
    a.environment,
    a.criticality,
    COUNT(t.ticket_id)                                          AS active_vulns,
    COALESCE(MAX(c.cvss_score), 0)                              AS worst_cvss,
    DENSE_RANK() OVER (PARTITION BY a.environment
                       ORDER BY COUNT(t.ticket_id) DESC,
                                COALESCE(MAX(c.cvss_score), 0) DESC) AS env_rank
FROM assets a
LEFT JOIN vuln_tickets t ON t.asset_id = a.asset_id AND t.status <> 'RESOLVED'
LEFT JOIN cve_records  c ON c.cve_id   = t.cve_id
GROUP BY a.asset_id, a.hostname, a.environment, a.criticality;

-- CVE catalogue with CWE name and live ticket counts (correlated subqueries)
CREATE OR REPLACE VIEW v_cve_catalog AS
SELECT
    c.cve_id,
    c.title,
    c.cwe_id,
    w.name AS cwe_name,
    c.cvss_score,
    c.severity,
    c.published_date,
    c.vector_sync_status,
    c.is_retired,
    (SELECT COUNT(*) FROM vuln_tickets t
       WHERE t.cve_id = c.cve_id AND t.status <> 'RESOLVED') AS open_tickets,
    (SELECT COUNT(DISTINCT t.asset_id) FROM vuln_tickets t
       WHERE t.cve_id = c.cve_id)                             AS affected_assets
FROM cve_records c
JOIN cwe_catalog w ON w.cwe_id = c.cwe_id;

-- Audit trail with human-readable context (read-only by construction)
CREATE OR REPLACE VIEW v_audit_trail AS
SELECT
    l.log_id,
    l.logged_at,
    l.ticket_id,
    a.hostname,
    t.cve_id,
    l.action_type,
    l.log_message,
    l.actor_user_id,
    COALESCE(u.full_name, 'SYSTEM') AS actor_name
FROM audit_logs l
JOIN vuln_tickets t ON t.ticket_id = l.ticket_id
JOIN assets       a ON a.asset_id  = t.asset_id
LEFT JOIN users   u ON u.user_id   = l.actor_user_id;

-- Directory of users WITHOUT password hashes (analysts read this, never `users`)
CREATE OR REPLACE VIEW v_user_directory AS
SELECT
    u.user_id,
    u.full_name,
    u.email,
    u.role,
    d.name AS department,
    u.is_active,
    u.created_at,
    u.last_login_at
FROM users u
JOIN departments d ON d.department_id = u.department_id;

-- CVEs whose PostgreSQL vector copy is missing or stale
CREATE OR REPLACE VIEW v_cves_pending_sync AS
SELECT cve_id, title, vector_sync_status, updated_at
FROM cve_records
WHERE vector_sync_status <> 'SYNCED' AND is_retired = FALSE;
