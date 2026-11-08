-- =====================================================================
-- File 09 - DDL demonstration: CREATE / ALTER / DROP, keys, constraints,
-- indexes, views.  Works on a scratch table so the real schema is untouched.
-- Run as the schema owner:  mysql -u root < 09_ddl_demo.sql
-- =====================================================================
USE zerodayhub_db;

-- CREATE a table with PK, FK, UNIQUE, CHECK, DEFAULT
DROP TABLE IF EXISTS ddl_demo_scan_runs;
CREATE TABLE ddl_demo_scan_runs (
    run_id     INT AUTO_INCREMENT PRIMARY KEY,
    asset_id   INT NOT NULL,
    scanner    VARCHAR(40) NOT NULL DEFAULT 'baseline',
    findings   INT NOT NULL DEFAULT 0,
    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_demo_scan_asset FOREIGN KEY (asset_id)
        REFERENCES assets(asset_id) ON DELETE CASCADE,
    CONSTRAINT chk_demo_findings CHECK (findings >= 0),
    CONSTRAINT uq_demo_scan UNIQUE (asset_id, started_at)
) ENGINE=InnoDB;

-- ALTER: add / modify / rename / drop columns, add constraints and indexes
ALTER TABLE ddl_demo_scan_runs ADD COLUMN duration_sec INT NULL AFTER findings;
ALTER TABLE ddl_demo_scan_runs MODIFY COLUMN scanner VARCHAR(80) NOT NULL DEFAULT 'baseline';
ALTER TABLE ddl_demo_scan_runs RENAME COLUMN duration_sec TO duration_seconds;
ALTER TABLE ddl_demo_scan_runs ADD CONSTRAINT chk_demo_duration CHECK (duration_seconds IS NULL OR duration_seconds >= 0);
ALTER TABLE ddl_demo_scan_runs ADD INDEX idx_demo_scanner (scanner);
CREATE INDEX idx_demo_started ON ddl_demo_scan_runs (started_at);

-- the constraints really work (each of these is expected to be rejected)
-- INSERT INTO ddl_demo_scan_runs (asset_id, findings) VALUES (1, -5);          -- CHECK violated
-- INSERT INTO ddl_demo_scan_runs (asset_id, findings) VALUES (9999, 1);        -- FK violated
INSERT INTO ddl_demo_scan_runs (asset_id, scanner, findings, duration_seconds)
VALUES (1, 'nessus-like', 12, 340), (2, 'nessus-like', 3, 95);
SELECT * FROM ddl_demo_scan_runs;

-- VIEW over the scratch table
CREATE OR REPLACE VIEW v_demo_scan_summary AS
SELECT a.hostname, COUNT(*) AS runs, SUM(r.findings) AS total_findings
FROM ddl_demo_scan_runs r JOIN assets a ON a.asset_id = r.asset_id
GROUP BY a.hostname;
SELECT * FROM v_demo_scan_summary;

-- inspect what was built
SHOW CREATE TABLE ddl_demo_scan_runs\G
SHOW INDEX FROM ddl_demo_scan_runs;

-- DROP: index, constraint, column, view, table
ALTER TABLE ddl_demo_scan_runs DROP INDEX idx_demo_scanner;
DROP INDEX idx_demo_started ON ddl_demo_scan_runs;
ALTER TABLE ddl_demo_scan_runs DROP CONSTRAINT chk_demo_duration;
ALTER TABLE ddl_demo_scan_runs DROP COLUMN duration_seconds;
DROP VIEW IF EXISTS v_demo_scan_summary;
DROP TABLE IF EXISTS ddl_demo_scan_runs;

SELECT 'DDL demo complete: scratch objects created, altered and dropped' AS result;
