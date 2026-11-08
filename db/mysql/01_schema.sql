-- =====================================================================
-- ZeroDayHub :: MySQL 8.0 relational core
-- File 01 - DDL: database, tables, constraints, indexes, ALTER
-- Rubric: Database Creation (DDL with constraints), Database Design
-- WARNING: drops and recreates the database (course/demo setup only).
-- =====================================================================

DROP DATABASE IF EXISTS zerodayhub_db;
CREATE DATABASE zerodayhub_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE zerodayhub_db;

-- ---------------------------------------------------------------------
-- departments: organisational units that own assets (via their users)
-- head_user_id is added later with ALTER TABLE (users <-> departments
-- reference each other, so one of the FKs must be added after both exist)
-- ---------------------------------------------------------------------
CREATE TABLE departments (
    department_id INT AUTO_INCREMENT PRIMARY KEY,
    name          VARCHAR(100) NOT NULL,
    head_user_id  INT NULL,
    CONSTRAINT uq_department_name UNIQUE (name),
    CONSTRAINT chk_department_name CHECK (CHAR_LENGTH(TRIM(name)) >= 2)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- users: accounts + RBAC role. Only salted bcrypt hashes are stored.
-- The CHECK on password_hash length rejects plain-text passwords at the
-- database level (a bcrypt hash is always 60 characters).
-- ---------------------------------------------------------------------
CREATE TABLE users (
    user_id       INT AUTO_INCREMENT PRIMARY KEY,
    full_name     VARCHAR(100) NOT NULL,
    email         VARCHAR(150) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role          ENUM('Security_Analyst','Asset_Owner','Admin') NOT NULL DEFAULT 'Asset_Owner',
    department_id INT NOT NULL,
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP NULL,
    CONSTRAINT uq_users_email UNIQUE (email),
    CONSTRAINT chk_users_email CHECK (email REGEXP '^[^@ ]+@[^@ ]+\\.[^@ ]+$'),
    CONSTRAINT chk_users_name CHECK (CHAR_LENGTH(TRIM(full_name)) >= 2),
    CONSTRAINT chk_users_pwhash CHECK (password_hash REGEXP '^\\$2[aby]\\$[0-9]{2}\\$.{53}$'),
    CONSTRAINT fk_users_department FOREIGN KEY (department_id)
        REFERENCES departments(department_id) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

-- circular reference resolved with ALTER TABLE (DDL requirement: ALTER)
ALTER TABLE departments
    ADD CONSTRAINT fk_department_head FOREIGN KEY (head_user_id)
        REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE;

-- ---------------------------------------------------------------------
-- assets: servers / endpoints / services that can be vulnerable
-- ---------------------------------------------------------------------
CREATE TABLE assets (
    asset_id    INT AUTO_INCREMENT PRIMARY KEY,
    hostname    VARCHAR(120) NOT NULL,
    ip_address  VARCHAR(45)  NOT NULL,
    environment ENUM('Production','Staging','Development') NOT NULL,
    os_version  VARCHAR(80)  NOT NULL DEFAULT 'Ubuntu 22.04 LTS',
    criticality ENUM('Low','Medium','High','Critical') NOT NULL,
    owner_id    INT NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT uq_assets_hostname UNIQUE (hostname),
    CONSTRAINT chk_assets_ip CHECK (INET6_ATON(ip_address) IS NOT NULL),
    CONSTRAINT chk_assets_hostname CHECK (hostname REGEXP '^[A-Za-z0-9][A-Za-z0-9._-]*$'),
    CONSTRAINT fk_assets_owner FOREIGN KEY (owner_id)
        REFERENCES users(user_id) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- asset_dependencies: directed graph "asset_id depends on depends_on_id".
-- Used by the recursive CTE that computes the blast radius.
-- ---------------------------------------------------------------------
CREATE TABLE asset_dependencies (
    asset_id            INT NOT NULL,
    depends_on_asset_id INT NOT NULL,
    relationship        ENUM('CALLS','HOSTED_ON','READS_DATA_FROM') NOT NULL DEFAULT 'CALLS',
    PRIMARY KEY (asset_id, depends_on_asset_id),
    -- "no self-dependency" cannot be a CHECK (MySQL forbids CHECKs on columns used in
    -- FK referential actions); it is enforced by trigger trg_dep_bi_validate instead.
    CONSTRAINT fk_dep_asset FOREIGN KEY (asset_id)
        REFERENCES assets(asset_id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_dep_target FOREIGN KEY (depends_on_asset_id)
        REFERENCES assets(asset_id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- cwe_catalog: weakness classes (3NF: CWE name depends on CWE id only)
-- ---------------------------------------------------------------------
CREATE TABLE cwe_catalog (
    cwe_id VARCHAR(12)  PRIMARY KEY,
    name   VARCHAR(120) NOT NULL,
    CONSTRAINT chk_cwe_id CHECK (cwe_id REGEXP '^CWE-[0-9]+$')
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- sla_policies: remediation window per severity (drives ticket deadlines)
-- ---------------------------------------------------------------------
CREATE TABLE sla_policies (
    severity ENUM('Low','Medium','High','Critical') PRIMARY KEY,
    sla_days INT NOT NULL,
    CONSTRAINT chk_sla_days CHECK (sla_days BETWEEN 1 AND 365)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- cve_records: master vulnerability catalogue (structured part).
-- Unstructured advisory text lives in PostgreSQL (pgvector); the two
-- stores are linked logically by cve_id. vector_sync_status tracks
-- whether the PostgreSQL copy is up to date.
-- severity is derived from cvss_score by trigger (see 05_triggers_events.sql)
-- ---------------------------------------------------------------------
CREATE TABLE cve_records (
    cve_id             VARCHAR(25)  PRIMARY KEY,
    title              VARCHAR(255) NOT NULL,
    cwe_id             VARCHAR(12)  NOT NULL,
    cvss_score         DECIMAL(3,1) NOT NULL,
    severity           ENUM('Low','Medium','High','Critical') NOT NULL DEFAULT 'Low',
    published_date     DATE NOT NULL,
    vector_sync_status ENUM('PENDING','SYNCED','FAILED') NOT NULL DEFAULT 'PENDING',
    is_retired         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT chk_cve_id_format CHECK (cve_id REGEXP '^CVE-[0-9]{4}-[0-9]{4,}$'),
    CONSTRAINT chk_cvss_bounds CHECK (cvss_score >= 0.0 AND cvss_score <= 10.0),
    CONSTRAINT chk_cve_title CHECK (CHAR_LENGTH(TRIM(title)) >= 5),
    CONSTRAINT fk_cve_cwe FOREIGN KEY (cwe_id)
        REFERENCES cwe_catalog(cwe_id) ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT fk_cve_severity FOREIGN KEY (severity)
        REFERENCES sla_policies(severity) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- vuln_tickets: bridge entity between assets and CVEs with a lifecycle
-- ---------------------------------------------------------------------
CREATE TABLE vuln_tickets (
    ticket_id               INT AUTO_INCREMENT PRIMARY KEY,
    asset_id                INT NOT NULL,
    cve_id                  VARCHAR(25) NOT NULL,
    assigned_analyst_id     INT NOT NULL,
    status                  ENUM('OPEN','IN_PROGRESS','RESOLVED','ESCALATED') NOT NULL DEFAULT 'OPEN',
    sla_deadline            DATETIME NOT NULL,
    resolved_at             DATETIME NULL,
    remediation_commit_hash VARCHAR(64) NULL,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT uq_ticket_asset_cve UNIQUE (asset_id, cve_id),
    CONSTRAINT chk_ticket_commit CHECK (remediation_commit_hash IS NULL
                                        OR remediation_commit_hash REGEXP '^[0-9a-f]{7,64}$'),
    CONSTRAINT chk_ticket_resolved_has_commit CHECK (status <> 'RESOLVED'
                                        OR remediation_commit_hash IS NOT NULL),
    CONSTRAINT fk_ticket_asset FOREIGN KEY (asset_id)
        REFERENCES assets(asset_id) ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT fk_ticket_cve FOREIGN KEY (cve_id)
        REFERENCES cve_records(cve_id) ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT fk_ticket_analyst FOREIGN KEY (assigned_analyst_id)
        REFERENCES users(user_id) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- patch_verifications: auditor decisions on submitted patches
-- ---------------------------------------------------------------------
CREATE TABLE patch_verifications (
    verification_id INT AUTO_INCREMENT PRIMARY KEY,
    ticket_id       INT NOT NULL,
    commit_hash     VARCHAR(64) NOT NULL,
    reviewer_id     INT NOT NULL,
    verdict         ENUM('VERIFIED','REJECTED') NOT NULL,
    notes           VARCHAR(500) NULL,
    reviewed_at     TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT fk_pv_ticket FOREIGN KEY (ticket_id)
        REFERENCES vuln_tickets(ticket_id) ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT fk_pv_reviewer FOREIGN KEY (reviewer_id)
        REFERENCES users(user_id) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- audit_logs: append-only ledger. Rows are written by triggers and
-- procedures; UPDATE/DELETE are blocked by triggers AND by privileges.
-- ---------------------------------------------------------------------
CREATE TABLE audit_logs (
    log_id        BIGINT AUTO_INCREMENT PRIMARY KEY,
    ticket_id     INT NOT NULL,
    actor_user_id INT NULL,
    action_type   VARCHAR(40) NOT NULL,
    log_message   VARCHAR(500) NOT NULL,
    logged_at     TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT fk_audit_ticket FOREIGN KEY (ticket_id)
        REFERENCES vuln_tickets(ticket_id) ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT fk_audit_actor FOREIGN KEY (actor_user_id)
        REFERENCES users(user_id) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Indexes (beyond PK / UNIQUE / FK indexes) chosen for real query paths
-- ---------------------------------------------------------------------
CREATE INDEX idx_tickets_status_sla ON vuln_tickets (status, sla_deadline);   -- SLA sweep + board
CREATE INDEX idx_tickets_analyst    ON vuln_tickets (assigned_analyst_id, status);
CREATE INDEX idx_assets_owner       ON assets (owner_id);
CREATE INDEX idx_assets_env_crit    ON assets (environment, criticality);
CREATE INDEX idx_cve_severity_cvss  ON cve_records (severity, cvss_score);
CREATE INDEX idx_cve_sync           ON cve_records (vector_sync_status);
CREATE INDEX idx_audit_ticket_time  ON audit_logs (ticket_id, logged_at);
CREATE INDEX idx_dep_target         ON asset_dependencies (depends_on_asset_id);
-- MySQL full-text search (keyword search over CVE titles)
CREATE FULLTEXT INDEX ft_cve_title ON cve_records (title);
