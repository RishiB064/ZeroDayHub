#!/usr/bin/env bash
# =====================================================================
# Database test-suite: integrity constraints, triggers, transactions and
# role-based access control (MySQL + PostgreSQL).
# Run AFTER `npm run db:init` (and optionally `npm run db:seed-vectors`).
#   bash db/tests/run-db-tests.sh            -> prints PASS/FAIL per case
# Every case states the expected outcome:  OK  or  FAIL:<text in the error>
# =====================================================================
set -uo pipefail
cd "$(dirname "$0")/../.."
set -a; . "./${ENV_FILE:-.env.local}"; set +a

MYSQL_HOST_T="${MYSQL_HOST:-localhost}"; [ "$MYSQL_HOST_T" = "localhost" ] && MYSQL_HOST_T=127.0.0.1
PASS=0; FAILN=0

msql_root() { MYSQL_PWD="${MYSQL_SETUP_PASSWORD:-}" mysql -h "${MYSQL_SETUP_HOST:-localhost}" -u "$MYSQL_SETUP_USER" -N -B "$MYSQL_DATABASE" -e "$1" 2>&1; }
msql_as()   { # $1 user $2 password $3 sql
  MYSQL_PWD="$2" mysql -h "$MYSQL_HOST_T" -P "${MYSQL_PORT:-3306}" -u "$1" -N -B "$MYSQL_DATABASE" -e "$3" 2>&1; }
psql_as()   { PGPASSWORD="$2" psql -h "${PG_HOST:-localhost}" -p "${PG_PORT:-5432}" -U "$1" -d "$PG_DATABASE" -tA -c "$3" 2>&1; }

check() { # id, description, expected, output, exit
  local id="$1" desc="$2" expect="$3" out="$4" rc="$5" ok=0
  case "$expect" in
    OK)      [ "$rc" -eq 0 ] && ok=1 ;;
    FAIL:*)  [ "$rc" -ne 0 ] && grep -qiF -- "${expect#FAIL:}" <<<"$out" && ok=1 ;;
    HAS:*)   [ "$rc" -eq 0 ] && grep -qF -- "${expect#HAS:}" <<<"$out" && ok=1 ;;
  esac
  if [ "$ok" -eq 1 ]; then PASS=$((PASS+1)); printf "PASS  %-10s %s\n" "$id" "$desc"
  else FAILN=$((FAILN+1)); printf "FAIL  %-10s %s\n        expected: %s\n        got     : %s\n" "$id" "$desc" "$expect" "$(head -c 300 <<<"$out")"; fi
}
t_root()    { out=$(msql_root "$4"); check "$1" "$2" "$3" "$out" $?; }
t_mysql()   { out=$(msql_as "$4" "$5" "$6"); check "$1" "$2" "$3" "$out" $?; }
t_pg()      { out=$(psql_as "$4" "$5" "$6"); check "$1" "$2" "$3" "$out" $?; }
# NB: $? above is the status of the command substitution assignment

A="$MYSQL_ANALYST_USER"; AP="$MYSQL_ANALYST_PASSWORD"
O="$MYSQL_OWNER_USER";   OP="$MYSQL_OWNER_PASSWORD"
M="$MYSQL_ADMIN_USER";   MP="$MYSQL_ADMIN_PASSWORD"
L="$MYSQL_AUTH_USER";    LP="$MYSQL_AUTH_PASSWORD"

echo "=== 1. Data validation & integrity (DB level) ==============================="
t_root T-INT-01 "plain-text password is rejected by CHECK on password_hash" "FAIL:chk_users_pwhash" \
  "INSERT INTO users (full_name,email,password_hash,role,department_id) VALUES ('Bad User','bad@zerodayhub.io','secret123','Admin',1)"
t_root T-INT-02 "invalid e-mail rejected" "FAIL:chk_users_email" \
  "INSERT INTO users (full_name,email,password_hash,role,department_id) VALUES ('Bad Mail','not-an-email','\$2a\$10\$vJwmz.O6h7YA7pMlWKbtVOiI6b4ku23qWi.YS40oTAQOCgTgzhNM.','Admin',1)"
t_root T-INT-03 "CVSS score above 10 rejected" "FAIL:chk_cvss_bounds" \
  "INSERT INTO cve_records (cve_id,title,cwe_id,cvss_score,published_date) VALUES ('CVE-2026-9001','Out of range score test','CWE-79',11.0,CURDATE())"
t_root T-INT-04 "malformed CVE id rejected" "FAIL:chk_cve_id_format" \
  "INSERT INTO cve_records (cve_id,title,cwe_id,cvss_score,published_date) VALUES ('CVE-26-1','Malformed id test record','CWE-79',5.0,CURDATE())"
t_root T-INT-05 "invalid IP address rejected" "FAIL:chk_assets_ip" \
  "INSERT INTO assets (hostname,ip_address,environment,criticality,owner_id) VALUES ('bad-ip-host','999.1.1.1','Staging','Low',5)"
t_root T-INT-06 "unknown CWE blocked by foreign key" "FAIL:fk_cve_cwe" \
  "INSERT INTO cve_records (cve_id,title,cwe_id,cvss_score,published_date) VALUES ('CVE-2026-9002','Unknown CWE test record','CWE-99999',5.0,CURDATE())"
t_root T-INT-07 "duplicate (asset, CVE) ticket blocked by UNIQUE" "FAIL:uq_ticket_asset_cve" \
  "INSERT INTO vuln_tickets (asset_id,cve_id,assigned_analyst_id,sla_deadline) VALUES (1,'CVE-2026-1001',2,NOW() + INTERVAL 1 DAY)"
t_root T-INT-08 "asset cannot depend on itself (trigger)" "FAIL:cannot depend on itself" \
  "INSERT INTO asset_dependencies (asset_id,depends_on_asset_id) VALUES (4,4)"
t_root T-INT-09 "last active admin cannot be deactivated (trigger)" "FAIL:last active admin" \
  "UPDATE users SET is_active = FALSE WHERE user_id = 1"
t_root T-INT-10 "ticket cannot be assigned to an asset owner (trigger)" "FAIL:active security analyst" \
  "INSERT INTO vuln_tickets (asset_id,cve_id,assigned_analyst_id,sla_deadline) VALUES (12,'CVE-2026-1001',5,NOW() + INTERVAL 1 DAY)"
t_root T-INT-11 "RESOLVED without a commit hash rejected" "FAIL:chk_ticket_resolved_has_commit" \
  "UPDATE vuln_tickets SET status='RESOLVED' WHERE ticket_id=3"
t_root T-INT-12 "resolved tickets are read-only (trigger)" "FAIL:read-only" \
  "UPDATE vuln_tickets SET assigned_analyst_id=3 WHERE ticket_id=14"
t_root T-INT-13 "severity derived from CVSS by trigger" "HAS:Critical" \
  "START TRANSACTION; INSERT INTO cve_records (cve_id,title,cwe_id,cvss_score,published_date) VALUES ('CVE-2026-9003','Severity derivation test','CWE-79',9.5,CURDATE()); SELECT severity FROM cve_records WHERE cve_id='CVE-2026-9003'; ROLLBACK;"
t_root T-INT-14 "overdue ticket auto-escalates on any update (trigger)" "HAS:ESCALATED" \
  "START TRANSACTION; UPDATE vuln_tickets SET sla_deadline = NOW() - INTERVAL 1 HOUR WHERE ticket_id=3; SELECT status FROM vuln_tickets WHERE ticket_id=3; ROLLBACK;"

echo "=== 2. Append-only audit log ================================================"
t_root T-AUD-01 "UPDATE on audit_logs blocked by trigger (even for root)" "FAIL:append-only" \
  "UPDATE audit_logs SET log_message='tampered' WHERE log_id=1"
t_root T-AUD-02 "DELETE on audit_logs blocked by trigger (even for root)" "FAIL:append-only" \
  "DELETE FROM audit_logs WHERE log_id=1"
t_root T-AUD-03 "ticket with audit history cannot be deleted (FK RESTRICT)" "FAIL:foreign key constraint" \
  "DELETE FROM vuln_tickets WHERE ticket_id=1"
t_root T-AUD-04 "SLA breach escalation was logged by the trigger" "HAS:SLA_BREACH_ESCALATION" \
  "SELECT DISTINCT action_type FROM audit_logs WHERE action_type='SLA_BREACH_ESCALATION'"

echo "=== 3. Transactions (sp_review_patch) ======================================="
BEFORE=$(msql_root "SELECT COUNT(*) FROM patch_verifications")
t_root T-TXN-01 "review without a submitted patch raises an error" "FAIL:No patch has been submitted" \
  "CALL sp_review_patch(3, 2, 'VERIFIED', 'should not apply')"
AFTER=$(msql_root "SELECT COUNT(*) FROM patch_verifications")
[ "$BEFORE" = "$AFTER" ] && { PASS=$((PASS+1)); echo "PASS  T-TXN-02   failed review left patch_verifications unchanged ($BEFORE rows)"; } \
  || { FAILN=$((FAILN+1)); echo "FAIL  T-TXN-02   rows changed $BEFORE -> $AFTER"; }
t_root T-TXN-03 "review by a non-analyst rejected" "FAIL:Reviewer must be an active analyst" \
  "CALL sp_review_patch(2, 5, 'VERIFIED', NULL)"
t_root T-TXN-04 "bad commit-hash format rejected on submit" "FAIL:chk_ticket_commit" \
  "CALL sp_submit_patch(3, 'NOT-A-HASH!', 8)"

echo "=== 4. RBAC in MySQL (each case connects as a different DB account) ========="
t_mysql T-RBAC-01 "analyst reads the ticket board" OK "$A" "$AP" "SELECT COUNT(*) FROM v_ticket_board"
t_mysql T-RBAC-02 "analyst cannot read users.password_hash" "FAIL:denied" "$A" "$AP" "SELECT password_hash FROM users"
t_mysql T-RBAC-03 "analyst cannot read the users table at all" "FAIL:denied" "$A" "$AP" "SELECT user_id FROM users"
t_mysql T-RBAC-04 "analyst reads the hash-free user directory" OK "$A" "$AP" "SELECT COUNT(*) FROM v_user_directory"
t_mysql T-RBAC-05 "analyst cannot change ticket status directly" "FAIL:denied" "$A" "$AP" "UPDATE vuln_tickets SET status='OPEN' WHERE ticket_id=0"
t_mysql T-RBAC-06 "analyst may reassign tickets (column-level grant)" OK "$A" "$AP" "UPDATE vuln_tickets SET assigned_analyst_id=2 WHERE ticket_id=0"
t_mysql T-RBAC-07 "analyst cannot modify assets" "FAIL:denied" "$A" "$AP" "UPDATE assets SET criticality='Low' WHERE asset_id=0"
t_mysql T-RBAC-08 "analyst cannot delete audit rows (privilege layer)" "FAIL:denied" "$A" "$AP" "DELETE FROM audit_logs WHERE log_id=0"
t_mysql T-RBAC-09 "analyst can insert CVEs" OK "$A" "$AP" "START TRANSACTION; INSERT INTO cve_records (cve_id,title,cwe_id,cvss_score,published_date) VALUES ('CVE-2026-9004','Analyst insert privilege test','CWE-79',5.0,CURDATE()); ROLLBACK;"
t_mysql T-RBAC-10 "owner has no direct access to assets" "FAIL:denied" "$O" "$OP" "SELECT * FROM assets"
t_mysql T-RBAC-11 "owner has no direct access to tickets" "FAIL:denied" "$O" "$OP" "SELECT * FROM vuln_tickets"
t_mysql T-RBAC-12 "owner has no access to audit logs" "FAIL:denied" "$O" "$OP" "SELECT * FROM audit_logs"
t_mysql T-RBAC-13 "owner reads own tickets through a procedure" OK "$O" "$OP" "CALL sp_owner_tickets(6)"
t_mysql T-RBAC-14 "owner reads the CVE catalogue" OK "$O" "$OP" "SELECT COUNT(*) FROM cve_records"
t_mysql T-RBAC-15 "owner cannot write CVEs" "FAIL:denied" "$O" "$OP" "DELETE FROM cve_records WHERE cve_id='x'"
t_mysql T-RBAC-16 "owner cannot triage tickets (no EXECUTE)" "FAIL:denied" "$O" "$OP" "CALL sp_triage_ticket(1,'CVE-2026-1003',2,5)"
t_mysql T-RBAC-17 "owner cannot patch another owner's ticket (ownership check inside DB)" "FAIL:Only the asset owner" "$O" "$OP" "CALL sp_submit_patch(1,'abc1234',5)"
t_mysql T-RBAC-18 "owner cannot retire another owner's asset" "FAIL:Not allowed" "$O" "$OP" "CALL sp_retire_asset(5,2)"
t_mysql T-RBAC-19 "owner cannot register assets for someone else" "FAIL:Not allowed" "$O" "$OP" "CALL sp_register_asset(5,6,'steal-host','10.9.9.9','Staging','', 'Low')"
t_mysql T-RBAC-19b "owner cannot call the ungated blast-radius procedure" "FAIL:denied" "$O" "$OP" "CALL sp_blast_radius(1)"
t_mysql T-RBAC-19c "owner cannot analyse another owner's asset" "FAIL:Not allowed" "$O" "$OP" "CALL sp_owner_blast_radius(5,1)"
t_mysql T-RBAC-19d "owner can analyse the blast radius of own asset" OK "$O" "$OP" "CALL sp_owner_blast_radius(6,3)"
t_mysql T-RBAC-20 "admin reads users" OK "$M" "$MP" "SELECT COUNT(*) FROM users"
t_mysql T-RBAC-21 "admin cannot delete audit rows" "FAIL:denied" "$M" "$MP" "DELETE FROM audit_logs WHERE log_id=0"
t_mysql T-RBAC-22 "admin cannot insert audit rows directly" "FAIL:denied" "$M" "$MP" "INSERT INTO audit_logs (ticket_id,action_type,log_message) VALUES (1,'FORGED','x')"
t_mysql T-RBAC-23 "admin cannot drop tables" "FAIL:denied" "$M" "$MP" "DROP TABLE departments"
t_mysql T-RBAC-24 "auth account reads login columns" OK "$L" "$LP" "SELECT user_id,email,password_hash,role,is_active FROM users WHERE email='x'"
t_mysql T-RBAC-25 "auth account cannot read other user columns" "FAIL:denied" "$L" "$LP" "SELECT department_id FROM users"
t_mysql T-RBAC-26 "auth account cannot read assets" "FAIL:denied" "$L" "$LP" "SELECT * FROM assets"

echo "=== 5. RBAC in PostgreSQL ===================================================="
t_pg T-PG-01 "reader can SELECT vectors" OK "$PG_READER_USER" "$PG_READER_PASSWORD" "SELECT count(*) FROM cve_threat_vectors"
t_pg T-PG-02 "reader cannot INSERT" "FAIL:permission denied" "$PG_READER_USER" "$PG_READER_PASSWORD" \
  "INSERT INTO cve_threat_vectors (cve_id,advisory_text,embedding,embedding_model,content_hash) VALUES ('CVE-2026-9999','x',NULL,'m','x')"
t_pg T-PG-03 "reader cannot DELETE" "FAIL:permission denied" "$PG_READER_USER" "$PG_READER_PASSWORD" "DELETE FROM cve_threat_vectors"
t_pg T-PG-04 "writer can DELETE (no rows matched)" OK "$PG_WRITER_USER" "$PG_WRITER_PASSWORD" "DELETE FROM cve_threat_vectors WHERE cve_id='CVE-0000-0000'"
t_pg T-PG-05 "writer cannot drop the table" "FAIL:must be owner" "$PG_WRITER_USER" "$PG_WRITER_PASSWORD" "DROP TABLE cve_threat_vectors"
t_pg T-PG-06 "CHECK rejects a malformed CVE id" "FAIL:chk_ctv_cve_id" "$PG_WRITER_USER" "$PG_WRITER_PASSWORD" \
  "INSERT INTO cve_threat_vectors (cve_id,advisory_text,embedding,embedding_model,content_hash) VALUES ('bad-id','this advisory text is long enough', array_fill(0.1::real, ARRAY[384])::vector, 'm', repeat('a',64))"
t_pg T-PG-07 "wrong embedding dimension rejected" "FAIL:expected 384 dimensions" "$PG_WRITER_USER" "$PG_WRITER_PASSWORD" \
  "INSERT INTO cve_threat_vectors (cve_id,advisory_text,embedding,embedding_model,content_hash) VALUES ('CVE-2026-9998','this advisory text is long enough', '[1,2,3]'::vector, 'm', repeat('a',64))"

echo
echo "RESULT: $PASS passed, $FAILN failed"
[ "$FAILN" -eq 0 ]
