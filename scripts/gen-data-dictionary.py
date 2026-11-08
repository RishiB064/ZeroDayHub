#!/usr/bin/env python3
"""Generates docs/DATA_DICTIONARY.md from the live MySQL + PostgreSQL catalogues.
Usage: set -a; . ./.env.local; set +a; python3 scripts/gen-data-dictionary.py"""
import os, subprocess

DB = os.environ.get("MYSQL_DATABASE", "zerodayhub_db")
def mysql(sql):
    env = dict(os.environ, MYSQL_PWD=os.environ.get("MYSQL_SETUP_PASSWORD", ""))
    out = subprocess.run(["mysql", f"-u{os.environ.get('MYSQL_SETUP_USER','root')}", "-N", "-B", DB, "-e", sql],
                         capture_output=True, text=True, check=True, env=env).stdout
    return [l.split("\t") for l in out.splitlines() if l]
def psql(sql):
    env = dict(os.environ, PGPASSWORD=os.environ.get("PG_SETUP_PASSWORD", ""))
    out = subprocess.run(["psql", "-h", os.environ.get("PG_HOST", "localhost"), "-U", os.environ.get("PG_SETUP_USER", "postgres"),
                          "-d", os.environ.get("PG_DATABASE", "zerodayhub_vectors"), "-Atc", sql],
                         capture_output=True, text=True, check=True, env=env).stdout
    return [l.split("|") for l in out.splitlines() if l]

PURPOSE = {
 "departments": "Organisational units that own assets (via their users).",
 "users": "Application accounts. Passwords are stored only as bcrypt hashes (enforced by a CHECK).",
 "assets": "Servers and services under governance, each with exactly one owner.",
 "asset_dependencies": "Directed graph edges between assets (used by the recursive blast-radius query).",
 "cwe_catalog": "Reference list of weakness types (CWE).",
 "sla_policies": "Remediation window in days for each severity.",
 "cve_records": "Structured CVE facts. Advisory text and embeddings live in PostgreSQL.",
 "vuln_tickets": "One row per (asset, CVE) pair being remediated. Core workflow table.",
 "patch_verifications": "History of every patch submission and the reviewer's verdict.",
 "audit_logs": "Append-only trail of ticket events (write-only through triggers and procedures).",
}
COL = {
 ("departments","department_id"):"Surrogate key.",("departments","name"):"Unique department name.",("departments","head_user_id"):"Department head (nullable; FK added with ALTER TABLE to break the users/departments cycle).",
 ("users","user_id"):"Surrogate key.",("users","full_name"):"Display name.",("users","email"):"Login name; unique; format validated by CHECK.",("users","password_hash"):"bcrypt hash ($2a/$2b/$2y); CHECK rejects anything else.",("users","role"):"RBAC role used by the application and mapped to a MySQL account.",("users","department_id"):"Department the user belongs to.",("users","is_active"):"0 disables login; the last active admin cannot be disabled (trigger).",("users","created_at"):"Creation time.",("users","last_login_at"):"Set after a successful sign-in.",
 ("assets","asset_id"):"Surrogate key.",("assets","hostname"):"Unique host name.",("assets","ip_address"):"IPv4/IPv6 text validated with INET6_ATON in a CHECK.",("assets","environment"):"Production, Staging or Development.",("assets","os_version"):"Operating system label.",("assets","criticality"):"Business criticality; feeds the risk index.",("assets","owner_id"):"Owning user (RESTRICT on delete).",("assets","created_at"):"Creation time.",("assets","updated_at"):"Last change.",
 ("asset_dependencies","asset_id"):"Asset that depends on another.",("asset_dependencies","depends_on_asset_id"):"Asset being depended on (CHECK: not the same asset).",("asset_dependencies","relationship"):"CALLS, HOSTED_ON or READS_DATA_FROM.",
 ("cwe_catalog","cwe_id"):"Identifier such as CWE-79.",("cwe_catalog","name"):"Weakness name.",
 ("sla_policies","severity"):"Severity level (PK).",("sla_policies","sla_days"):"Days allowed before breach.",
 ("cve_records","cve_id"):"CVE-YYYY-NNNN+ (CHECK format).",("cve_records","title"):"Short title; FULLTEXT indexed.",("cve_records","cwe_id"):"Weakness class.",("cve_records","cvss_score"):"CVSS base score 0.0-10.0.",("cve_records","severity"):"Derived from the score by trigger; FK to sla_policies.",("cve_records","published_date"):"Public disclosure date.",("cve_records","vector_sync_status"):"PENDING, SYNCED or FAILED: state of the copy in PostgreSQL.",("cve_records","is_retired"):"Soft delete for CVEs that still have tickets.",("cve_records","created_at"):"Creation time.",("cve_records","updated_at"):"Last change.",
 ("vuln_tickets","ticket_id"):"Surrogate key.",("vuln_tickets","asset_id"):"Affected asset.",("vuln_tickets","cve_id"):"Vulnerability.",("vuln_tickets","assigned_analyst_id"):"Analyst responsible (trigger forbids owners).",("vuln_tickets","status"):"OPEN, IN_PROGRESS, RESOLVED, ESCALATED.",("vuln_tickets","sla_deadline"):"Set by sp_triage_ticket from sla_policies.",("vuln_tickets","resolved_at"):"Set when verified.",("vuln_tickets","remediation_commit_hash"):"Commit that fixes the issue; required (CHECK) for RESOLVED.",("vuln_tickets","created_at"):"Creation time.",("vuln_tickets","updated_at"):"Last change.",
 ("patch_verifications","verification_id"):"Surrogate key.",("patch_verifications","ticket_id"):"Ticket reviewed.",("patch_verifications","commit_hash"):"Submitted commit (7-64 hex).",("patch_verifications","reviewer_id"):"Analyst/admin who reviewed (NOT NULL once reviewed).",("patch_verifications","verdict"):"VERIFIED or REJECTED.",("patch_verifications","notes"):"Free-text reason.",("patch_verifications","reviewed_at"):"Millisecond timestamp.",
 ("audit_logs","log_id"):"Monotonic key.",("audit_logs","ticket_id"):"Ticket concerned.",("audit_logs","actor_user_id"):"Who acted; NULL means SYSTEM (scheduler/trigger).",("audit_logs","action_type"):"TICKET_CREATED, PATCH_SUBMITTED, ...",("audit_logs","log_message"):"Human-readable detail.",("audit_logs","logged_at"):"Millisecond timestamp.",
}
PGCOL = {"cve_id":"Logical foreign key to MySQL cve_records.cve_id (CHECK format).","advisory_text":"Text that is embedded together with the title and CWE name.","exploit_summary":"How the flaw is exploited (also embedded).","remediation_playbook":"Fix steps (shown, not embedded).","metadata":"JSONB filters: severity, cvss, cwe, vendor, product, tags.","embedding":"384-dimension L2-normalised sentence embedding.","embedding_model":"Model that produced the vector; searches only compare like with like.","content_hash":"SHA-256 of the embedded text; unchanged text is never re-embedded.","search_tsv":"Generated tsvector for hybrid full-text ranking.","created_at":"Creation time.","updated_at":"Touched by trigger on every update."}

o = ["# Data dictionary\n", "Generated from the live catalogues by `scripts/gen-data-dictionary.py`.\n", "## MySQL 8 (`zerodayhub_db`)\n"]
tables = [r[0] for r in mysql("select table_name from information_schema.tables where table_schema='%s' and table_type='BASE TABLE' order by table_name" % DB)]
order = ["departments","users","assets","asset_dependencies","cwe_catalog","sla_policies","cve_records","vuln_tickets","patch_verifications","audit_logs"]
for t in [x for x in order if x in tables]:
    o.append(f"### `{t}`\n\n{PURPOSE.get(t,'')}\n")
    o.append("| Column | Type | Null | Key | Default | Description |\n|---|---|---|---|---|---|")
    for c,ty,nl,key,df,ex in mysql(f"select column_name,column_type,is_nullable,column_key,ifnull(column_default,''),extra from information_schema.columns where table_schema='{DB}' and table_name='{t}' order by ordinal_position"):
        k = {"PRI":"PK","UNI":"UNIQUE","MUL":"index"}.get(key, "")
        o.append(f"| `{c}` | {ty} | {nl} | {k} | {df.replace('|','/')} | {COL.get((t,c),'')} |")
    chk = mysql(f"select cc.constraint_name, cc.check_clause from information_schema.check_constraints cc join information_schema.table_constraints tc on tc.constraint_name=cc.constraint_name and tc.constraint_schema=cc.constraint_schema where tc.table_schema='{DB}' and tc.table_name='{t}'")
    if chk:
        o.append("\nCHECK constraints: " + "; ".join(f"`{n}`" for n,_ in chk) + "\n")
    else: o.append("")
o.append("### Foreign keys\n\n| Constraint | From | To | ON DELETE |\n|---|---|---|---|")
for n,tb,col,rt,rc,dr in mysql(f"select k.constraint_name,k.table_name,k.column_name,k.referenced_table_name,k.referenced_column_name,r.delete_rule from information_schema.key_column_usage k join information_schema.referential_constraints r on r.constraint_name=k.constraint_name and r.constraint_schema=k.table_schema where k.table_schema='{DB}' and k.referenced_table_name is not null order by k.table_name"):
    o.append(f"| `{n}` | {tb}.{col} | {rt}.{rc} | {dr} |")
o.append("\n### Views, routines, triggers and events\n")
for kind, sql in [("Views","select table_name from information_schema.views where table_schema='%s' order by 1"),("Functions","select routine_name from information_schema.routines where routine_schema='%s' and routine_type='FUNCTION' order by 1"),("Procedures","select routine_name from information_schema.routines where routine_schema='%s' and routine_type='PROCEDURE' order by 1"),("Triggers","select trigger_name from information_schema.triggers where trigger_schema='%s' order by 1"),("Events","select event_name from information_schema.events where event_schema='%s'")]:
    names = [r[0] for r in mysql(sql % DB)]
    o.append(f"- **{kind} ({len(names)})**: " + ", ".join(f"`{n}`" for n in names))
o.append("\n## PostgreSQL 16 + pgvector (`zerodayhub_vectors`)\n\n### `cve_threat_vectors`\n\nDerived semantic index: one row per CVE that has advisory text.\n")
o.append("| Column | Type | Null | Default | Description |\n|---|---|---|---|---|")
for c,ty,nl,df in psql("select column_name, case when data_type='USER-DEFINED' then udt_name||'(384)' else data_type end, is_nullable, coalesce(replace(column_default,'|','/'),'') from information_schema.columns where table_name='cve_threat_vectors' order by ordinal_position"):
    o.append(f"| `{c}` | {ty} | {nl} | {df} | {PGCOL.get(c,'')} |")
o.append("\nIndexes:\n")
for n,d in psql("select indexname, indexdef from pg_indexes where tablename='cve_threat_vectors' order by 1"):
    o.append(f"- `{n}`: `{d.split(' USING ',1)[1]}`")
o.append("\nFunctions: " + ", ".join(f"`{r[0]}`" for r in psql("select proname from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and proname like 'fn\\_%' order by 1")) + "; view `v_vector_stats`.\n")
open("docs/DATA_DICTIONARY.md","w").write("\n".join(o)+"\n")
print("written")
