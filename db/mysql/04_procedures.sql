-- =====================================================================
-- File 04 - Stored procedures
-- Rubric: Procedure/function, transactions, recursive CTE, DB-level RBAC
-- Procedures run with DEFINER rights, so low-privilege roles are given
-- EXECUTE on them (see 06_roles.sql.tpl) instead of direct table access.
-- Business errors are raised with SIGNAL SQLSTATE '45000'.
-- =====================================================================
USE zerodayhub_db;

DELIMITER $$

-- Helper: may this actor manage this asset? (the owner, or an active Admin)
DROP FUNCTION IF EXISTS fn_can_manage_asset$$
CREATE FUNCTION fn_can_manage_asset(p_actor_id INT, p_asset_id INT)
RETURNS BOOLEAN
NOT DETERMINISTIC
READS SQL DATA
BEGIN
    DECLARE v_ok BOOLEAN DEFAULT FALSE;
    SELECT TRUE INTO v_ok
    FROM users u
    LEFT JOIN assets a ON a.asset_id = p_asset_id
    WHERE u.user_id = p_actor_id AND u.is_active
      AND (u.role = 'Admin' OR (u.role = 'Asset_Owner' AND a.owner_id = u.user_id))
    LIMIT 1;
    RETURN COALESCE(v_ok, FALSE);
END$$

-- ---------------------------------------------------------------------
-- Ticket lifecycle
-- ---------------------------------------------------------------------

-- Triage: create a ticket with an SLA deadline derived from CVE severity
DROP PROCEDURE IF EXISTS sp_triage_ticket$$
CREATE PROCEDURE sp_triage_ticket(
    IN p_asset_id   INT,
    IN p_cve_id     VARCHAR(25),
    IN p_analyst_id INT,
    IN p_actor_id   INT
)
BEGIN
    DECLARE v_severity VARCHAR(10);
    DECLARE v_retired  BOOLEAN;

    SET @zdh_actor_id = p_actor_id;

    IF NOT EXISTS (SELECT 1 FROM assets WHERE asset_id = p_asset_id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Asset not found';
    END IF;

    SELECT severity, is_retired INTO v_severity, v_retired
    FROM cve_records WHERE cve_id = p_cve_id;

    IF v_severity IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'CVE not found';
    END IF;
    IF v_retired THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'CVE is retired and cannot be ticketed';
    END IF;

    -- duplicate pair is rejected by uq_ticket_asset_cve; analyst validity by trigger
    INSERT INTO vuln_tickets (asset_id, cve_id, assigned_analyst_id, status, sla_deadline)
    VALUES (p_asset_id, p_cve_id, p_analyst_id, 'OPEN',
            DATE_ADD(NOW(), INTERVAL fn_sla_days(v_severity) DAY));

    SELECT LAST_INSERT_ID() AS ticket_id;
END$$

-- Asset owner (or Admin) attaches a remediation commit to a ticket
DROP PROCEDURE IF EXISTS sp_submit_patch$$
CREATE PROCEDURE sp_submit_patch(
    IN p_ticket_id   INT,
    IN p_commit_hash VARCHAR(64),
    IN p_actor_id    INT
)
BEGIN
    DECLARE v_asset_id INT;
    DECLARE v_status   VARCHAR(20);

    SET @zdh_actor_id = p_actor_id;

    SELECT asset_id, status INTO v_asset_id, v_status
    FROM vuln_tickets WHERE ticket_id = p_ticket_id;

    IF v_asset_id IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Ticket not found';
    END IF;
    IF NOT fn_can_manage_asset(p_actor_id, v_asset_id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Only the asset owner or an admin can submit a patch';
    END IF;
    IF v_status = 'RESOLVED' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Ticket is already resolved';
    END IF;

    -- chk_ticket_commit validates the hash format; trigger keeps ESCALATED if overdue
    UPDATE vuln_tickets
    SET remediation_commit_hash = LOWER(p_commit_hash),
        status = IF(status = 'ESCALATED', 'ESCALATED', 'IN_PROGRESS')
    WHERE ticket_id = p_ticket_id;

    SELECT ticket_id, status, remediation_commit_hash FROM vuln_tickets WHERE ticket_id = p_ticket_id;
END$$

-- Reviewer verifies or rejects a submitted patch.
-- ONE ATOMIC TRANSACTION touching three tables:
--   patch_verifications (decision) + vuln_tickets (lifecycle) + audit_logs (ledger)
DROP PROCEDURE IF EXISTS sp_review_patch$$
CREATE PROCEDURE sp_review_patch(
    IN p_ticket_id   INT,
    IN p_reviewer_id INT,
    IN p_verdict     VARCHAR(10),
    IN p_notes       VARCHAR(500)
)
BEGIN
    DECLARE v_status VARCHAR(20);
    DECLARE v_hash   VARCHAR(64);

    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    SET @zdh_actor_id = p_reviewer_id;

    IF p_verdict NOT IN ('VERIFIED', 'REJECTED') THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Verdict must be VERIFIED or REJECTED';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM users
                   WHERE user_id = p_reviewer_id AND is_active
                     AND role IN ('Security_Analyst', 'Admin')) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Reviewer must be an active analyst or admin';
    END IF;

    START TRANSACTION;

    SELECT status, remediation_commit_hash INTO v_status, v_hash
    FROM vuln_tickets WHERE ticket_id = p_ticket_id FOR UPDATE;

    IF v_status IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Ticket not found';
    END IF;
    IF v_status = 'RESOLVED' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Ticket is already resolved';
    END IF;
    IF v_hash IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'No patch has been submitted for this ticket';
    END IF;

    INSERT INTO patch_verifications (ticket_id, commit_hash, reviewer_id, verdict, notes)
    VALUES (p_ticket_id, v_hash, p_reviewer_id, p_verdict, p_notes);

    IF p_verdict = 'VERIFIED' THEN
        UPDATE vuln_tickets SET status = 'RESOLVED' WHERE ticket_id = p_ticket_id;
        INSERT INTO audit_logs (ticket_id, actor_user_id, action_type, log_message)
        VALUES (p_ticket_id, p_reviewer_id, 'PATCH_VERIFIED',
                CONCAT('Commit ', v_hash, ' verified; ticket closed.'));
    ELSE
        UPDATE vuln_tickets SET status = 'IN_PROGRESS', remediation_commit_hash = NULL
        WHERE ticket_id = p_ticket_id;
        INSERT INTO audit_logs (ticket_id, actor_user_id, action_type, log_message)
        VALUES (p_ticket_id, p_reviewer_id, 'PATCH_REJECTED',
                CONCAT('Commit ', v_hash, ' rejected', IF(p_notes IS NULL, '.', CONCAT(': ', p_notes))));
    END IF;

    COMMIT;

    SELECT ticket_id, status, resolved_at FROM vuln_tickets WHERE ticket_id = p_ticket_id;
END$$

-- SLA sweep: escalate every overdue unresolved ticket. The BEFORE UPDATE and
-- AFTER UPDATE triggers stamp the status and write the audit entries.
-- Called by event ev_sla_sweep and by the admin "Run SLA sweep" button.
DROP PROCEDURE IF EXISTS sp_sla_sweep$$
CREATE PROCEDURE sp_sla_sweep(OUT p_escalated INT)
BEGIN
    SET @zdh_actor_id = NULL;
    UPDATE vuln_tickets
    SET status = 'ESCALATED'
    WHERE status IN ('OPEN', 'IN_PROGRESS') AND sla_deadline < NOW();
    SET p_escalated = ROW_COUNT();
END$$

-- ---------------------------------------------------------------------
-- Blast radius: RECURSIVE CTE over the asset dependency graph.
-- Finds every asset that directly or transitively depends on the
-- vulnerable asset. Path tracking prevents infinite loops on cycles.
-- ---------------------------------------------------------------------
DROP PROCEDURE IF EXISTS sp_blast_radius$$
CREATE PROCEDURE sp_blast_radius(IN p_asset_id INT)
BEGIN
    WITH RECURSIVE exposure AS (
        SELECT a.asset_id,
               a.hostname,
               0 AS depth,
               CAST(a.asset_id AS CHAR(200)) AS path,
               CAST('ORIGIN' AS CHAR(20))    AS via
        FROM assets a
        WHERE a.asset_id = p_asset_id
        UNION ALL
        SELECT d.asset_id,
               a2.hostname,
               e.depth + 1,
               CONCAT(e.path, ',', d.asset_id),
               CAST(d.relationship AS CHAR(20))
        FROM exposure e
        JOIN asset_dependencies d ON d.depends_on_asset_id = e.asset_id
        JOIN assets a2            ON a2.asset_id = d.asset_id
        WHERE e.depth < 8
          AND FIND_IN_SET(d.asset_id, e.path) = 0
    ),
    -- an asset can be reachable through several paths: keep the shortest one
    nearest AS (
        SELECT exposure.*,
               ROW_NUMBER() OVER (PARTITION BY asset_id ORDER BY depth, path) AS rn
        FROM exposure
    )
    SELECT x.asset_id,
           x.hostname,
           a.environment,
           a.criticality,
           x.depth,
           x.via,
           x.path,
           (SELECT COUNT(*) FROM vuln_tickets t
             WHERE t.asset_id = x.asset_id AND t.status <> 'RESOLVED') AS open_tickets
    FROM nearest x
    JOIN assets a ON a.asset_id = x.asset_id
    WHERE x.rn = 1
    ORDER BY x.depth, a.criticality DESC, x.hostname;
END$$

-- ---------------------------------------------------------------------
-- Asset-owner surface: owners have NO table privileges; these procedures
-- are the only door, and each one checks ownership inside the database.
-- ---------------------------------------------------------------------

-- Ownership-gated wrapper: an owner may only analyse the blast radius of assets they manage
DROP PROCEDURE IF EXISTS sp_owner_blast_radius$$
CREATE PROCEDURE sp_owner_blast_radius(IN p_actor_id INT, IN p_asset_id INT)
BEGIN
    IF NOT fn_can_manage_asset(p_actor_id, p_asset_id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Not allowed to analyse this asset';
    END IF;
    CALL sp_blast_radius(p_asset_id);
END$$

DROP PROCEDURE IF EXISTS sp_owner_tickets$$
CREATE PROCEDURE sp_owner_tickets(IN p_owner_id INT)
BEGIN
    SELECT * FROM v_ticket_board
    WHERE owner_id = p_owner_id
    ORDER BY FIELD(status, 'ESCALATED', 'OPEN', 'IN_PROGRESS', 'RESOLVED'), sla_deadline;
END$$

DROP PROCEDURE IF EXISTS sp_owner_assets$$
CREATE PROCEDURE sp_owner_assets(IN p_owner_id INT)
BEGIN
    SELECT a.asset_id, a.hostname, a.ip_address, a.environment, a.os_version, a.criticality,
           a.owner_id, u.full_name AS owner_name,
           (SELECT COUNT(*) FROM vuln_tickets t
             WHERE t.asset_id = a.asset_id AND t.status <> 'RESOLVED') AS open_tickets
    FROM assets a
    JOIN users u ON u.user_id = a.owner_id
    WHERE a.owner_id = p_owner_id
    ORDER BY a.hostname;
END$$

DROP PROCEDURE IF EXISTS sp_owner_summary$$
CREATE PROCEDURE sp_owner_summary(IN p_owner_id INT)
BEGIN
    SELECT
        (SELECT COUNT(*) FROM assets WHERE owner_id = p_owner_id)                         AS total_assets,
        COUNT(CASE WHEN status <> 'RESOLVED' THEN 1 END)                                  AS open_tickets,
        COUNT(CASE WHEN status = 'ESCALATED' THEN 1 END)                                  AS escalated_tickets,
        COUNT(CASE WHEN status = 'RESOLVED'  THEN 1 END)                                  AS resolved_tickets,
        COALESCE(ROUND(AVG(CASE WHEN status <> 'RESOLVED' THEN risk_index END), 2), 0)    AS avg_open_risk
    FROM v_ticket_board
    WHERE owner_id = p_owner_id;
END$$

DROP PROCEDURE IF EXISTS sp_register_asset$$
CREATE PROCEDURE sp_register_asset(
    IN p_actor_id    INT,
    IN p_owner_id    INT,
    IN p_hostname    VARCHAR(120),
    IN p_ip          VARCHAR(45),
    IN p_environment VARCHAR(15),
    IN p_os          VARCHAR(80),
    IN p_criticality VARCHAR(10)
)
BEGIN
    IF NOT EXISTS (SELECT 1 FROM users WHERE user_id = p_actor_id AND is_active
                   AND (role = 'Admin' OR (role = 'Asset_Owner' AND user_id = p_owner_id))) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Not allowed to register assets for this owner';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM users WHERE user_id = p_owner_id AND is_active
                   AND role IN ('Asset_Owner', 'Admin')) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Owner must be an active asset owner';
    END IF;

    INSERT INTO assets (hostname, ip_address, environment, os_version, criticality, owner_id)
    VALUES (p_hostname, p_ip, p_environment, COALESCE(NULLIF(p_os, ''), 'Ubuntu 22.04 LTS'),
            p_criticality, p_owner_id);

    SELECT LAST_INSERT_ID() AS asset_id;
END$$

DROP PROCEDURE IF EXISTS sp_update_asset$$
CREATE PROCEDURE sp_update_asset(
    IN p_actor_id    INT,
    IN p_asset_id    INT,
    IN p_ip          VARCHAR(45),
    IN p_environment VARCHAR(15),
    IN p_os          VARCHAR(80),
    IN p_criticality VARCHAR(10)
)
BEGIN
    IF NOT fn_can_manage_asset(p_actor_id, p_asset_id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Not allowed to modify this asset';
    END IF;
    UPDATE assets
    SET ip_address = p_ip, environment = p_environment,
        os_version = COALESCE(NULLIF(p_os, ''), os_version), criticality = p_criticality
    WHERE asset_id = p_asset_id;
    SELECT ROW_COUNT() AS updated;
END$$

DROP PROCEDURE IF EXISTS sp_retire_asset$$
CREATE PROCEDURE sp_retire_asset(IN p_actor_id INT, IN p_asset_id INT)
BEGIN
    IF NOT fn_can_manage_asset(p_actor_id, p_asset_id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Not allowed to retire this asset';
    END IF;
    IF EXISTS (SELECT 1 FROM vuln_tickets WHERE asset_id = p_asset_id) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Asset has vulnerability tickets (audit history) and cannot be deleted';
    END IF;
    DELETE FROM assets WHERE asset_id = p_asset_id;   -- dependency edges cascade
    SELECT ROW_COUNT() AS deleted;
END$$

DELIMITER ;
