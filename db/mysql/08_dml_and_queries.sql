-- =====================================================================
-- File 08 - DML operations and important queries (demo script)
-- Rubric: DML operations; nested / correlated / recursive queries; joins
-- Run as the schema owner AFTER the seed:   mysql -u root < 08_dml_and_queries.sql
-- Part A runs inside a transaction that is rolled back, so the seed data is
-- left untouched and the script can be repeated.
-- =====================================================================
USE zerodayhub_db;

-- =====================================================================
-- PART A  -  DML: INSERT / UPDATE / DELETE / SELECT
-- =====================================================================
START TRANSACTION;
SET @zdh_actor_id = 1;

-- A1 INSERT: new critical CVE; severity is derived by trigger from the score
INSERT INTO cve_records (cve_id, title, cwe_id, cvss_score, published_date)
VALUES ('CVE-2026-2001', 'Granite cache daemon integer overflow in length parsing', 'CWE-190', 10.0, CURDATE());
SELECT cve_id, cvss_score, severity FROM cve_records WHERE cve_id = 'CVE-2026-2001';

-- A2 INSERT ... SELECT: open a ticket for EVERY critical production asset
INSERT INTO vuln_tickets (asset_id, cve_id, assigned_analyst_id, status, sla_deadline)
SELECT a.asset_id, 'CVE-2026-2001', 2, 'OPEN', DATE_ADD(NOW(), INTERVAL fn_sla_days('Critical') DAY)
FROM assets a
WHERE a.environment = 'Production' AND a.criticality = 'Critical';
SELECT ticket_id, asset_id, cve_id, status, sla_deadline FROM vuln_tickets WHERE cve_id = 'CVE-2026-2001';

-- A3 INSERT with scalar subqueries for the foreign keys
INSERT INTO assets (hostname, ip_address, environment, os_version, criticality, owner_id)
VALUES ('prod-cache-01', '10.120.4.77', 'Production', 'Ubuntu 24.04 LTS', 'High',
        (SELECT user_id FROM users WHERE email = 'rohan.devops@zerodayhub.io'));

-- A4 UPDATE: CVSS re-scored, trigger moves the severity band
UPDATE cve_records SET cvss_score = 6.4 WHERE cve_id = 'CVE-2026-2001';
SELECT cve_id, cvss_score, severity FROM cve_records WHERE cve_id = 'CVE-2026-2001';

-- A5 UPDATE: reassign one analyst's active work to another (trigger writes REASSIGNED audit rows)
UPDATE vuln_tickets
SET assigned_analyst_id = 4
WHERE assigned_analyst_id = 3 AND status IN ('OPEN', 'IN_PROGRESS');
SELECT ticket_id, assigned_analyst_id, status FROM vuln_tickets WHERE assigned_analyst_id = 4 ORDER BY ticket_id;

-- A6 UPDATE with JOIN: raise criticality of every staging asset owned by Core Payments
UPDATE assets a
JOIN users u ON u.user_id = a.owner_id
JOIN departments d ON d.department_id = u.department_id
SET a.criticality = 'Critical'
WHERE a.environment = 'Staging' AND d.name = 'Core Payments';

-- A7 DELETE: remove a dependency edge, then a CVE that has no tickets
DELETE FROM asset_dependencies WHERE asset_id = 11 AND depends_on_asset_id = 10;
-- (tickets cannot be deleted once they have audit history: audit_logs.ticket_id is ON DELETE RESTRICT)
SELECT COUNT(*) AS audit_rows_for_new_cve FROM audit_logs al JOIN vuln_tickets t ON t.ticket_id = al.ticket_id
WHERE t.cve_id = 'CVE-2026-2001';

ROLLBACK;   -- seed data restored

-- A8 DELETE that succeeds permanently-safe inside its own rolled-back unit
START TRANSACTION;
INSERT INTO cve_records (cve_id, title, cwe_id, cvss_score, published_date)
VALUES ('CVE-2026-2002', 'Temporary record created to demonstrate DELETE', 'CWE-79', 3.1, CURDATE());
DELETE FROM cve_records WHERE cve_id = 'CVE-2026-2002';
SELECT COUNT(*) AS should_be_zero FROM cve_records WHERE cve_id = 'CVE-2026-2002';
ROLLBACK;

-- =====================================================================
-- PART B  -  Important queries
-- =====================================================================

-- B1 Multi-table INNER JOIN (5 tables): open work ordered by risk
SELECT a.hostname, a.environment, u.full_name AS asset_owner, c.cve_id, c.cvss_score, c.severity,
       t.status AS ticket_status, t.sla_deadline,
       fn_risk_index(c.cvss_score, a.criticality) AS risk_index
FROM vuln_tickets t
JOIN assets      a ON a.asset_id = t.asset_id
JOIN users       u ON u.user_id  = a.owner_id
JOIN cve_records c ON c.cve_id   = t.cve_id
WHERE t.status <> 'RESOLVED'
ORDER BY risk_index DESC, t.sla_deadline
LIMIT 10;

-- B2 LEFT JOIN + GROUP BY + HAVING + aggregate: owners with 2+ assets
SELECT u.full_name, d.name AS department, COUNT(a.asset_id) AS assets_owned,
       SUM(a.criticality = 'Critical') AS critical_assets
FROM users u
JOIN departments d ON d.department_id = u.department_id
LEFT JOIN assets a ON a.owner_id = u.user_id
WHERE u.role = 'Asset_Owner'
GROUP BY u.user_id, u.full_name, d.name
HAVING COUNT(a.asset_id) >= 2
ORDER BY assets_owned DESC;

-- B3 Subquery with IN: CVEs that touch production assets
SELECT cve_id, title, cvss_score
FROM cve_records
WHERE cve_id IN (SELECT t.cve_id FROM vuln_tickets t
                 JOIN assets a ON a.asset_id = t.asset_id
                 WHERE a.environment = 'Production')
ORDER BY cvss_score DESC;

-- B4 Scalar subquery: tickets whose CVSS is above the catalogue average
SELECT t.ticket_id, a.hostname, c.cve_id, c.cvss_score,
       (SELECT ROUND(AVG(cvss_score), 2) FROM cve_records) AS catalogue_avg
FROM vuln_tickets t
JOIN assets a ON a.asset_id = t.asset_id
JOIN cve_records c ON c.cve_id = t.cve_id
WHERE c.cvss_score > (SELECT AVG(cvss_score) FROM cve_records)
ORDER BY c.cvss_score DESC;

-- B5 Correlated subquery with EXISTS: analysts that currently own active tickets
SELECT u.user_id, u.full_name
FROM users u
WHERE u.role = 'Security_Analyst'
  AND EXISTS (SELECT 1 FROM vuln_tickets t
              WHERE t.assigned_analyst_id = u.user_id AND t.status <> 'RESOLVED');

-- B6 Correlated subquery: assets riskier than the average of their own environment
SELECT a.hostname, a.environment, ROUND(AVG(c.cvss_score), 2) AS asset_avg_cvss
FROM assets a
JOIN vuln_tickets t ON t.asset_id = a.asset_id AND t.status <> 'RESOLVED'
JOIN cve_records  c ON c.cve_id   = t.cve_id
GROUP BY a.asset_id, a.hostname, a.environment
HAVING AVG(c.cvss_score) > (
    SELECT AVG(c2.cvss_score)
    FROM assets a2
    JOIN vuln_tickets t2 ON t2.asset_id = a2.asset_id AND t2.status <> 'RESOLVED'
    JOIN cve_records  c2 ON c2.cve_id   = t2.cve_id
    WHERE a2.environment = a.environment            -- correlated on the outer row
);

-- B7 RECURSIVE CTE (stored procedure): blast radius of the payment database.
--    Includes the 3 <-> 6 cycle, which the path check terminates.
CALL sp_blast_radius(3);

-- B8 RECURSIVE CTE: SLA workload forecast for the next 7 days
WITH RECURSIVE days AS (
    SELECT CURDATE() AS day
    UNION ALL
    SELECT DATE_ADD(day, INTERVAL 1 DAY) FROM days WHERE day < DATE_ADD(CURDATE(), INTERVAL 6 DAY)
)
SELECT d.day, DAYNAME(d.day) AS weekday, COUNT(t.ticket_id) AS deadlines_due
FROM days d
LEFT JOIN vuln_tickets t ON DATE(t.sla_deadline) = d.day AND t.status <> 'RESOLVED'
GROUP BY d.day
ORDER BY d.day;

-- B9 Non-recursive CTE + window function (also exposed as a view): department ranking
SELECT * FROM v_department_risk ORDER BY risk_rank, department;

-- B10 Window function: top-2 riskiest assets inside each environment tier
SELECT environment, hostname, active_vulns, worst_cvss, env_rank
FROM v_asset_exposure
WHERE env_rank <= 2
ORDER BY environment, env_rank, hostname;

-- B11 Derived table (subquery in FROM) + CASE: SLA health summary
SELECT health, COUNT(*) AS tickets
FROM (SELECT CASE WHEN status = 'RESOLVED'              THEN 'Resolved'
                  WHEN fn_is_sla_breached(sla_deadline, status) THEN 'Breached'
                  WHEN sla_deadline < DATE_ADD(NOW(), INTERVAL 2 DAY) THEN 'Due soon'
                  ELSE 'On track' END AS health
      FROM vuln_tickets) s
GROUP BY health
ORDER BY FIELD(health, 'Breached', 'Due soon', 'On track', 'Resolved');

-- B12 GROUP BY ... WITH ROLLUP: tickets per environment and status with subtotals
SELECT COALESCE(a.environment, 'ALL ENVIRONMENTS') AS environment,
       COALESCE(t.status, 'ALL STATUSES')           AS status,
       COUNT(*) AS tickets
FROM vuln_tickets t JOIN assets a ON a.asset_id = t.asset_id
GROUP BY a.environment, t.status WITH ROLLUP;

-- B13 FULL-TEXT search (MySQL FULLTEXT index on cve_records.title)
SELECT cve_id, title, MATCH(title) AGAINST ('injection' IN NATURAL LANGUAGE MODE) AS relevance
FROM cve_records
WHERE MATCH(title) AGAINST ('injection' IN NATURAL LANGUAGE MODE)
ORDER BY relevance DESC;

-- B14 UNION: one timeline of what happened to a ticket (audit + verification decisions)
SELECT logged_at AS happened_at, action_type AS event, log_message AS detail
FROM audit_logs WHERE ticket_id = 16
UNION ALL
SELECT reviewed_at, CONCAT('REVIEW_', verdict), COALESCE(notes, '')
FROM patch_verifications WHERE ticket_id = 16
ORDER BY happened_at;

-- B15 Procedure-backed owner view (what the Asset_Owner role is allowed to call)
CALL sp_owner_summary(6);
CALL sp_owner_tickets(6);
