-- =====================================================================
-- File 02 - Stored functions
-- Rubric: Advanced concepts (procedure / function / trigger / CTE)
-- Run after 01_schema.sql.   mysql> source 02_functions.sql
-- =====================================================================
USE zerodayhub_db;

DELIMITER $$

-- Weighted risk index: CVSS x asset criticality weight (pure, deterministic)
DROP FUNCTION IF EXISTS fn_risk_index$$
CREATE FUNCTION fn_risk_index(p_cvss DECIMAL(3,1), p_criticality VARCHAR(20))
RETURNS DECIMAL(5,2)
DETERMINISTIC
NO SQL
BEGIN
    DECLARE v_weight DECIMAL(3,2);
    CASE p_criticality
        WHEN 'Critical' THEN SET v_weight = 2.00;
        WHEN 'High'     THEN SET v_weight = 1.50;
        WHEN 'Medium'   THEN SET v_weight = 1.20;
        ELSE                 SET v_weight = 1.00;
    END CASE;
    RETURN ROUND(p_cvss * v_weight, 2);
END$$

-- Severity band from a CVSS v3 base score
DROP FUNCTION IF EXISTS fn_severity_from_cvss$$
CREATE FUNCTION fn_severity_from_cvss(p_cvss DECIMAL(3,1))
RETURNS VARCHAR(10)
DETERMINISTIC
NO SQL
BEGIN
    IF p_cvss >= 9.0 THEN RETURN 'Critical';
    ELSEIF p_cvss >= 7.0 THEN RETURN 'High';
    ELSEIF p_cvss >= 4.0 THEN RETURN 'Medium';
    END IF;
    RETURN 'Low';
END$$

-- SLA breach test: depends on the clock, so NOT DETERMINISTIC
DROP FUNCTION IF EXISTS fn_is_sla_breached$$
CREATE FUNCTION fn_is_sla_breached(p_deadline DATETIME, p_status VARCHAR(25))
RETURNS BOOLEAN
NOT DETERMINISTIC
NO SQL
BEGIN
    IF p_status = 'RESOLVED' THEN
        RETURN FALSE;
    END IF;
    RETURN NOW() > p_deadline;
END$$

-- SLA window (days) looked up from the policy table
DROP FUNCTION IF EXISTS fn_sla_days$$
CREATE FUNCTION fn_sla_days(p_severity VARCHAR(10))
RETURNS INT
NOT DETERMINISTIC
READS SQL DATA
BEGIN
    DECLARE v_days INT;
    SELECT sla_days INTO v_days FROM sla_policies WHERE severity = p_severity;
    RETURN COALESCE(v_days, 30);
END$$

DELIMITER ;
