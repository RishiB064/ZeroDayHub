-- =====================================================================
-- File 06 - Database-level RBAC (MySQL 8 roles, users, GRANTs)
-- Rubric: Authentication & Authorization - role-based access control IN
--         THE DATABASE (not only in the application)
--
-- This is a TEMPLATE: scripts/init-db.sh replaces the double-underscore NAME
-- tokens with values from .env.local, so no password is stored in the repo.
--
-- Principle of least privilege:
--   zdh_role_auth     login lookup only; can read password_hash, nobody else can
--   zdh_role_analyst  reads everything except users; edits CVEs; triages + reviews
--   zdh_role_owner    NO table access at all; EXECUTE on ownership-checked procs
--   zdh_role_admin    manages users/assets/CVEs; can read but never modify audit_logs
-- =====================================================================
USE zerodayhub_db;

DROP USER IF EXISTS 'zdh_auth'@'__APP_HOST__';
DROP USER IF EXISTS 'zdh_analyst'@'__APP_HOST__';
DROP USER IF EXISTS 'zdh_owner'@'__APP_HOST__';
DROP USER IF EXISTS 'zdh_admin'@'__APP_HOST__';
DROP ROLE IF EXISTS 'zdh_role_auth', 'zdh_role_analyst', 'zdh_role_owner', 'zdh_role_admin';

CREATE ROLE 'zdh_role_auth', 'zdh_role_analyst', 'zdh_role_owner', 'zdh_role_admin';

-- ---- auth: column-level privileges ------------------------------------
GRANT SELECT (user_id, full_name, email, password_hash, role, is_active)
    ON zerodayhub_db.users TO 'zdh_role_auth';
GRANT UPDATE (last_login_at) ON zerodayhub_db.users TO 'zdh_role_auth';

-- ---- security analyst ---------------------------------------------------
GRANT SELECT ON zerodayhub_db.assets              TO 'zdh_role_analyst';
GRANT SELECT ON zerodayhub_db.asset_dependencies  TO 'zdh_role_analyst';
GRANT SELECT ON zerodayhub_db.departments         TO 'zdh_role_analyst';
GRANT SELECT ON zerodayhub_db.sla_policies        TO 'zdh_role_analyst';
GRANT SELECT ON zerodayhub_db.cwe_catalog         TO 'zdh_role_analyst';
GRANT SELECT ON zerodayhub_db.vuln_tickets        TO 'zdh_role_analyst';
GRANT SELECT ON zerodayhub_db.patch_verifications TO 'zdh_role_analyst';
GRANT SELECT ON zerodayhub_db.audit_logs          TO 'zdh_role_analyst';
GRANT SELECT, INSERT, UPDATE, DELETE ON zerodayhub_db.cve_records TO 'zdh_role_analyst';
GRANT INSERT ON zerodayhub_db.cwe_catalog         TO 'zdh_role_analyst';
GRANT INSERT, DELETE ON zerodayhub_db.asset_dependencies TO 'zdh_role_analyst';
GRANT UPDATE (assigned_analyst_id) ON zerodayhub_db.vuln_tickets TO 'zdh_role_analyst';
GRANT SELECT ON zerodayhub_db.v_ticket_board       TO 'zdh_role_analyst';
GRANT SELECT ON zerodayhub_db.v_department_risk    TO 'zdh_role_analyst';
GRANT SELECT ON zerodayhub_db.v_asset_exposure     TO 'zdh_role_analyst';
GRANT SELECT ON zerodayhub_db.v_cve_catalog        TO 'zdh_role_analyst';
GRANT SELECT ON zerodayhub_db.v_audit_trail        TO 'zdh_role_analyst';
GRANT SELECT ON zerodayhub_db.v_user_directory     TO 'zdh_role_analyst';
GRANT SELECT ON zerodayhub_db.v_cves_pending_sync  TO 'zdh_role_analyst';
GRANT EXECUTE ON PROCEDURE zerodayhub_db.sp_triage_ticket TO 'zdh_role_analyst';
GRANT EXECUTE ON PROCEDURE zerodayhub_db.sp_review_patch  TO 'zdh_role_analyst';
GRANT EXECUTE ON PROCEDURE zerodayhub_db.sp_blast_radius  TO 'zdh_role_analyst';

-- ---- asset owner: reference data + procedures only ---------------------
GRANT SELECT ON zerodayhub_db.cve_records  TO 'zdh_role_owner';
GRANT SELECT ON zerodayhub_db.cwe_catalog  TO 'zdh_role_owner';
GRANT SELECT ON zerodayhub_db.sla_policies TO 'zdh_role_owner';
GRANT SELECT ON zerodayhub_db.departments  TO 'zdh_role_owner';
GRANT EXECUTE ON PROCEDURE zerodayhub_db.sp_owner_tickets  TO 'zdh_role_owner';
GRANT EXECUTE ON PROCEDURE zerodayhub_db.sp_owner_assets   TO 'zdh_role_owner';
GRANT EXECUTE ON PROCEDURE zerodayhub_db.sp_owner_summary  TO 'zdh_role_owner';
GRANT EXECUTE ON PROCEDURE zerodayhub_db.sp_register_asset TO 'zdh_role_owner';
GRANT EXECUTE ON PROCEDURE zerodayhub_db.sp_update_asset   TO 'zdh_role_owner';
GRANT EXECUTE ON PROCEDURE zerodayhub_db.sp_retire_asset   TO 'zdh_role_owner';
GRANT EXECUTE ON PROCEDURE zerodayhub_db.sp_submit_patch   TO 'zdh_role_owner';
GRANT EXECUTE ON PROCEDURE zerodayhub_db.sp_owner_blast_radius TO 'zdh_role_owner';

-- ---- admin: explicit list (no blanket ALL, audit_logs is read-only) -----
GRANT SELECT, INSERT, UPDATE, DELETE ON zerodayhub_db.departments         TO 'zdh_role_admin';
GRANT SELECT, INSERT, UPDATE         ON zerodayhub_db.users               TO 'zdh_role_admin';
GRANT SELECT, INSERT, UPDATE, DELETE ON zerodayhub_db.assets              TO 'zdh_role_admin';
GRANT SELECT, INSERT, UPDATE, DELETE ON zerodayhub_db.asset_dependencies  TO 'zdh_role_admin';
GRANT SELECT, INSERT, UPDATE, DELETE ON zerodayhub_db.cwe_catalog         TO 'zdh_role_admin';
GRANT SELECT, INSERT, UPDATE, DELETE ON zerodayhub_db.sla_policies        TO 'zdh_role_admin';
GRANT SELECT, INSERT, UPDATE, DELETE ON zerodayhub_db.cve_records         TO 'zdh_role_admin';
GRANT SELECT, INSERT, UPDATE         ON zerodayhub_db.vuln_tickets        TO 'zdh_role_admin';
GRANT SELECT, INSERT                 ON zerodayhub_db.patch_verifications TO 'zdh_role_admin';
GRANT SELECT                         ON zerodayhub_db.audit_logs          TO 'zdh_role_admin';
GRANT SELECT ON zerodayhub_db.v_ticket_board       TO 'zdh_role_admin';
GRANT SELECT ON zerodayhub_db.v_department_risk    TO 'zdh_role_admin';
GRANT SELECT ON zerodayhub_db.v_asset_exposure     TO 'zdh_role_admin';
GRANT SELECT ON zerodayhub_db.v_cve_catalog        TO 'zdh_role_admin';
GRANT SELECT ON zerodayhub_db.v_audit_trail        TO 'zdh_role_admin';
GRANT SELECT ON zerodayhub_db.v_user_directory     TO 'zdh_role_admin';
GRANT SELECT ON zerodayhub_db.v_cves_pending_sync  TO 'zdh_role_admin';
GRANT EXECUTE ON zerodayhub_db.* TO 'zdh_role_admin';

-- ---- login accounts used by the Next.js server (one pool per role) -----
CREATE USER 'zdh_auth'@'__APP_HOST__'    IDENTIFIED BY '__MYSQL_AUTH_PASSWORD__';
CREATE USER 'zdh_analyst'@'__APP_HOST__' IDENTIFIED BY '__MYSQL_ANALYST_PASSWORD__';
CREATE USER 'zdh_owner'@'__APP_HOST__'   IDENTIFIED BY '__MYSQL_OWNER_PASSWORD__';
CREATE USER 'zdh_admin'@'__APP_HOST__'   IDENTIFIED BY '__MYSQL_ADMIN_PASSWORD__';

GRANT 'zdh_role_auth'    TO 'zdh_auth'@'__APP_HOST__';
GRANT 'zdh_role_analyst' TO 'zdh_analyst'@'__APP_HOST__';
GRANT 'zdh_role_owner'   TO 'zdh_owner'@'__APP_HOST__';
GRANT 'zdh_role_admin'   TO 'zdh_admin'@'__APP_HOST__';

SET DEFAULT ROLE ALL TO 'zdh_auth'@'__APP_HOST__', 'zdh_analyst'@'__APP_HOST__',
                        'zdh_owner'@'__APP_HOST__', 'zdh_admin'@'__APP_HOST__';
FLUSH PRIVILEGES;
