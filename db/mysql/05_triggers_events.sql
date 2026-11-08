-- =====================================================================
-- File 05 - Triggers and the scheduled event
-- Rubric: Triggers (advanced concepts), data validation at DB level,
--         data integrity / consistency
-- Run after 04_procedures.sql.
-- =====================================================================
USE zerodayhub_db;

DELIMITER $$

-- ---- users: never lock the organisation out of its last admin ---------
DROP TRIGGER IF EXISTS trg_users_bu_guard$$
CREATE TRIGGER trg_users_bu_guard
BEFORE UPDATE ON users
FOR EACH ROW
BEGIN
    IF OLD.role = 'Admin' AND OLD.is_active = TRUE
       AND (NEW.is_active = FALSE OR NEW.role <> 'Admin')
       AND (SELECT COUNT(*) FROM users
            WHERE role = 'Admin' AND is_active = TRUE AND user_id <> OLD.user_id) = 0 THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Cannot demote or deactivate the last active admin';
    END IF;
END$$

-- ---- asset_dependencies: no self edges --------------------------------
DROP TRIGGER IF EXISTS trg_dep_bi_validate$$
CREATE TRIGGER trg_dep_bi_validate
BEFORE INSERT ON asset_dependencies
FOR EACH ROW
BEGIN
    IF NEW.asset_id = NEW.depends_on_asset_id THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'An asset cannot depend on itself';
    END IF;
END$$

DROP TRIGGER IF EXISTS trg_dep_bu_validate$$
CREATE TRIGGER trg_dep_bu_validate
BEFORE UPDATE ON asset_dependencies
FOR EACH ROW
BEGIN
    IF NEW.asset_id = NEW.depends_on_asset_id THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'An asset cannot depend on itself';
    END IF;
END$$

-- ---- cve_records: severity is always derived from the CVSS score ------
DROP TRIGGER IF EXISTS trg_cve_bi_severity$$
CREATE TRIGGER trg_cve_bi_severity
BEFORE INSERT ON cve_records
FOR EACH ROW
BEGIN
    SET NEW.severity = fn_severity_from_cvss(NEW.cvss_score);
END$$

DROP TRIGGER IF EXISTS trg_cve_bu_severity$$
CREATE TRIGGER trg_cve_bu_severity
BEFORE UPDATE ON cve_records
FOR EACH ROW
BEGIN
    SET NEW.severity = fn_severity_from_cvss(NEW.cvss_score);
END$$

-- ---- vuln_tickets: validation before insert ----------------------------
DROP TRIGGER IF EXISTS trg_ticket_bi_validate$$
CREATE TRIGGER trg_ticket_bi_validate
BEFORE INSERT ON vuln_tickets
FOR EACH ROW
BEGIN
    IF NOT EXISTS (SELECT 1 FROM users
                   WHERE user_id = NEW.assigned_analyst_id AND is_active
                     AND role IN ('Security_Analyst', 'Admin')) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Assignee must be an active security analyst or admin';
    END IF;
    IF EXISTS (SELECT 1 FROM cve_records WHERE cve_id = NEW.cve_id AND is_retired) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'CVE is retired and cannot be ticketed';
    END IF;
END$$

-- ---- vuln_tickets: lifecycle rules + SLA escalation (BEFORE UPDATE) ----
DROP TRIGGER IF EXISTS trg_ticket_bu_lifecycle$$
CREATE TRIGGER trg_ticket_bu_lifecycle
BEFORE UPDATE ON vuln_tickets
FOR EACH ROW
BEGIN
    -- the (asset, CVE) identity of a ticket never changes
    IF NEW.asset_id <> OLD.asset_id OR NEW.cve_id <> OLD.cve_id THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Ticket asset and CVE cannot be changed';
    END IF;
    -- RESOLVED is terminal
    IF OLD.status = 'RESOLVED' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Resolved tickets are read-only';
    END IF;
    -- an analyst must stay valid on reassignment
    IF NEW.assigned_analyst_id <> OLD.assigned_analyst_id
       AND NOT EXISTS (SELECT 1 FROM users
                       WHERE user_id = NEW.assigned_analyst_id AND is_active
                         AND role IN ('Security_Analyst', 'Admin')) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Assignee must be an active security analyst or admin';
    END IF;
    -- stamp resolution time
    IF NEW.status = 'RESOLVED' THEN
        SET NEW.resolved_at = NOW();
    END IF;
    -- SLA breach: any touch of an overdue open ticket escalates it
    IF NEW.status IN ('OPEN', 'IN_PROGRESS') AND NOW() > NEW.sla_deadline THEN
        SET NEW.status = 'ESCALATED';
    END IF;
END$$

-- ---- audit: ticket creation -------------------------------------------
DROP TRIGGER IF EXISTS trg_ticket_ai_audit$$
CREATE TRIGGER trg_ticket_ai_audit
AFTER INSERT ON vuln_tickets
FOR EACH ROW
BEGIN
    INSERT INTO audit_logs (ticket_id, actor_user_id, action_type, log_message)
    VALUES (NEW.ticket_id, @zdh_actor_id, 'TICKET_CREATED',
            CONCAT('Ticket opened for ', NEW.cve_id, ' with SLA deadline ', NEW.sla_deadline, '.'));
END$$

-- ---- audit: status changes, SLA breaches, patches, reassignment ---------
DROP TRIGGER IF EXISTS trg_ticket_au_audit$$
CREATE TRIGGER trg_ticket_au_audit
AFTER UPDATE ON vuln_tickets
FOR EACH ROW
BEGIN
    IF NEW.status <> OLD.status THEN
        IF NEW.status = 'ESCALATED' AND NOW() > NEW.sla_deadline THEN
            INSERT INTO audit_logs (ticket_id, actor_user_id, action_type, log_message)
            VALUES (NEW.ticket_id, NULL, 'SLA_BREACH_ESCALATION',
                    CONCAT('Ticket #', NEW.ticket_id, ' crossed its SLA deadline (',
                           NEW.sla_deadline, ') and was auto-escalated.'));
        ELSE
            INSERT INTO audit_logs (ticket_id, actor_user_id, action_type, log_message)
            VALUES (NEW.ticket_id, @zdh_actor_id, 'STATUS_CHANGED',
                    CONCAT('Status ', OLD.status, ' -> ', NEW.status, '.'));
        END IF;
    END IF;

    IF NEW.remediation_commit_hash IS NOT NULL
       AND (OLD.remediation_commit_hash IS NULL
            OR NEW.remediation_commit_hash <> OLD.remediation_commit_hash) THEN
        INSERT INTO audit_logs (ticket_id, actor_user_id, action_type, log_message)
        VALUES (NEW.ticket_id, @zdh_actor_id, 'PATCH_SUBMITTED',
                CONCAT('Remediation commit ', NEW.remediation_commit_hash, ' attached.'));
    END IF;

    IF NEW.assigned_analyst_id <> OLD.assigned_analyst_id THEN
        INSERT INTO audit_logs (ticket_id, actor_user_id, action_type, log_message)
        VALUES (NEW.ticket_id, @zdh_actor_id, 'REASSIGNED',
                CONCAT('Assigned analyst changed from user ', OLD.assigned_analyst_id,
                       ' to user ', NEW.assigned_analyst_id, '.'));
    END IF;
END$$

-- ---- audit_logs is append-only (trigger layer; privileges are layer two) -
DROP TRIGGER IF EXISTS trg_audit_bu_immutable$$
CREATE TRIGGER trg_audit_bu_immutable
BEFORE UPDATE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs is append-only: UPDATE is not allowed';
END$$

DROP TRIGGER IF EXISTS trg_audit_bd_immutable$$
CREATE TRIGGER trg_audit_bd_immutable
BEFORE DELETE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs is append-only: DELETE is not allowed';
END$$

DELIMITER ;

-- ---------------------------------------------------------------------
-- Event: a trigger only fires on writes, never because time passed, so a
-- scheduled event "touches" overdue tickets every 5 minutes. The event
-- scheduler must be ON (needs SYSTEM_VARIABLES_ADMIN; run as root).
-- ---------------------------------------------------------------------
SET GLOBAL event_scheduler = ON;

DROP EVENT IF EXISTS ev_sla_sweep;
CREATE EVENT ev_sla_sweep
    ON SCHEDULE EVERY 5 MINUTE
    DO CALL sp_sla_sweep(@zdh_event_escalated);
