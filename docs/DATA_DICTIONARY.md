# Data dictionary

Generated from the live catalogues by `scripts/gen-data-dictionary.py`.

## MySQL 8 (`zerodayhub_db`)

### `departments`

Organisational units that own assets (via their users).

| Column | Type | Null | Key | Default | Description |
|---|---|---|---|---|---|
| `department_id` | int | NO | PK |  | Surrogate key. |
| `name` | varchar(100) | NO | UNIQUE |  | Unique department name. |
| `head_user_id` | int | YES | index |  | Department head (nullable; FK added with ALTER TABLE to break the users/departments cycle). |

CHECK constraints: `chk_department_name`

### `users`

Application accounts. Passwords are stored only as bcrypt hashes (enforced by a CHECK).

| Column | Type | Null | Key | Default | Description |
|---|---|---|---|---|---|
| `user_id` | int | NO | PK |  | Surrogate key. |
| `full_name` | varchar(100) | NO |  |  | Display name. |
| `email` | varchar(150) | NO | UNIQUE |  | Login name; unique; format validated by CHECK. |
| `password_hash` | varchar(255) | NO |  |  | bcrypt hash ($2a/$2b/$2y); CHECK rejects anything else. |
| `role` | enum('Security_Analyst','Asset_Owner','Admin') | NO |  | Asset_Owner | RBAC role used by the application and mapped to a MySQL account. |
| `department_id` | int | NO | index |  | Department the user belongs to. |
| `is_active` | tinyint(1) | NO |  | 1 | 0 disables login; the last active admin cannot be disabled (trigger). |
| `created_at` | timestamp | NO |  | CURRENT_TIMESTAMP | Creation time. |
| `last_login_at` | timestamp | YES |  |  | Set after a successful sign-in. |

CHECK constraints: `chk_users_email`; `chk_users_name`; `chk_users_pwhash`

### `assets`

Servers and services under governance, each with exactly one owner.

| Column | Type | Null | Key | Default | Description |
|---|---|---|---|---|---|
| `asset_id` | int | NO | PK |  | Surrogate key. |
| `hostname` | varchar(120) | NO | UNIQUE |  | Unique host name. |
| `ip_address` | varchar(45) | NO |  |  | IPv4/IPv6 text validated with INET6_ATON in a CHECK. |
| `environment` | enum('Production','Staging','Development') | NO | index |  | Production, Staging or Development. |
| `os_version` | varchar(80) | NO |  | Ubuntu 22.04 LTS | Operating system label. |
| `criticality` | enum('Low','Medium','High','Critical') | NO |  |  | Business criticality; feeds the risk index. |
| `owner_id` | int | NO | index |  | Owning user (RESTRICT on delete). |
| `created_at` | timestamp | NO |  | CURRENT_TIMESTAMP | Creation time. |
| `updated_at` | timestamp | NO |  | CURRENT_TIMESTAMP | Last change. |

CHECK constraints: `chk_assets_hostname`; `chk_assets_ip`

### `asset_dependencies`

Directed graph edges between assets (used by the recursive blast-radius query).

| Column | Type | Null | Key | Default | Description |
|---|---|---|---|---|---|
| `asset_id` | int | NO | PK |  | Asset that depends on another. |
| `depends_on_asset_id` | int | NO | PK |  | Asset being depended on (CHECK: not the same asset). |
| `relationship` | enum('CALLS','HOSTED_ON','READS_DATA_FROM') | NO |  | CALLS | CALLS, HOSTED_ON or READS_DATA_FROM. |

### `cwe_catalog`

Reference list of weakness types (CWE).

| Column | Type | Null | Key | Default | Description |
|---|---|---|---|---|---|
| `cwe_id` | varchar(12) | NO | PK |  | Identifier such as CWE-79. |
| `name` | varchar(120) | NO |  |  | Weakness name. |

CHECK constraints: `chk_cwe_id`

### `sla_policies`

Remediation window in days for each severity.

| Column | Type | Null | Key | Default | Description |
|---|---|---|---|---|---|
| `severity` | enum('Low','Medium','High','Critical') | NO | PK |  | Severity level (PK). |
| `sla_days` | int | NO |  |  | Days allowed before breach. |

CHECK constraints: `chk_sla_days`

### `cve_records`

Structured CVE facts. Advisory text and embeddings live in PostgreSQL.

| Column | Type | Null | Key | Default | Description |
|---|---|---|---|---|---|
| `cve_id` | varchar(25) | NO | PK |  | CVE-YYYY-NNNN+ (CHECK format). |
| `title` | varchar(255) | NO | index |  | Short title; FULLTEXT indexed. |
| `cwe_id` | varchar(12) | NO | index |  | Weakness class. |
| `cvss_score` | decimal(3,1) | NO |  |  | CVSS base score 0.0-10.0. |
| `severity` | enum('Low','Medium','High','Critical') | NO | index | Low | Derived from the score by trigger; FK to sla_policies. |
| `published_date` | date | NO |  |  | Public disclosure date. |
| `vector_sync_status` | enum('PENDING','SYNCED','FAILED') | NO | index | PENDING | PENDING, SYNCED or FAILED: state of the copy in PostgreSQL. |
| `is_retired` | tinyint(1) | NO |  | 0 | Soft delete for CVEs that still have tickets. |
| `created_at` | timestamp | NO |  | CURRENT_TIMESTAMP | Creation time. |
| `updated_at` | timestamp | NO |  | CURRENT_TIMESTAMP | Last change. |

CHECK constraints: `chk_cve_id_format`; `chk_cve_title`; `chk_cvss_bounds`

### `vuln_tickets`

One row per (asset, CVE) pair being remediated. Core workflow table.

| Column | Type | Null | Key | Default | Description |
|---|---|---|---|---|---|
| `ticket_id` | int | NO | PK |  | Surrogate key. |
| `asset_id` | int | NO | index |  | Affected asset. |
| `cve_id` | varchar(25) | NO | index |  | Vulnerability. |
| `assigned_analyst_id` | int | NO | index |  | Analyst responsible (trigger forbids owners). |
| `status` | enum('OPEN','IN_PROGRESS','RESOLVED','ESCALATED') | NO | index | OPEN | OPEN, IN_PROGRESS, RESOLVED, ESCALATED. |
| `sla_deadline` | datetime | NO |  |  | Set by sp_triage_ticket from sla_policies. |
| `resolved_at` | datetime | YES |  |  | Set when verified. |
| `remediation_commit_hash` | varchar(64) | YES |  |  | Commit that fixes the issue; required (CHECK) for RESOLVED. |
| `created_at` | timestamp | NO |  | CURRENT_TIMESTAMP | Creation time. |
| `updated_at` | timestamp | NO |  | CURRENT_TIMESTAMP | Last change. |

CHECK constraints: `chk_ticket_commit`; `chk_ticket_resolved_has_commit`

### `patch_verifications`

History of every patch submission and the reviewer's verdict.

| Column | Type | Null | Key | Default | Description |
|---|---|---|---|---|---|
| `verification_id` | int | NO | PK |  | Surrogate key. |
| `ticket_id` | int | NO | index |  | Ticket reviewed. |
| `commit_hash` | varchar(64) | NO |  |  | Submitted commit (7-64 hex). |
| `reviewer_id` | int | NO | index |  | Analyst/admin who reviewed (NOT NULL once reviewed). |
| `verdict` | enum('VERIFIED','REJECTED') | NO |  |  | VERIFIED or REJECTED. |
| `notes` | varchar(500) | YES |  |  | Free-text reason. |
| `reviewed_at` | timestamp(3) | NO |  | CURRENT_TIMESTAMP(3) | Millisecond timestamp. |

### `audit_logs`

Append-only trail of ticket events (write-only through triggers and procedures).

| Column | Type | Null | Key | Default | Description |
|---|---|---|---|---|---|
| `log_id` | bigint | NO | PK |  | Monotonic key. |
| `ticket_id` | int | NO | index |  | Ticket concerned. |
| `actor_user_id` | int | YES | index |  | Who acted; NULL means SYSTEM (scheduler/trigger). |
| `action_type` | varchar(40) | NO |  |  | TICKET_CREATED, PATCH_SUBMITTED, ... |
| `log_message` | varchar(500) | NO |  |  | Human-readable detail. |
| `logged_at` | timestamp(3) | NO |  | CURRENT_TIMESTAMP(3) | Millisecond timestamp. |

### Foreign keys

| Constraint | From | To | ON DELETE |
|---|---|---|---|
| `fk_dep_asset` | asset_dependencies.asset_id | assets.asset_id | CASCADE |
| `fk_dep_target` | asset_dependencies.depends_on_asset_id | assets.asset_id | CASCADE |
| `fk_assets_owner` | assets.owner_id | users.user_id | RESTRICT |
| `fk_audit_actor` | audit_logs.actor_user_id | users.user_id | RESTRICT |
| `fk_audit_ticket` | audit_logs.ticket_id | vuln_tickets.ticket_id | RESTRICT |
| `fk_cve_cwe` | cve_records.cwe_id | cwe_catalog.cwe_id | RESTRICT |
| `fk_cve_severity` | cve_records.severity | sla_policies.severity | RESTRICT |
| `fk_department_head` | departments.head_user_id | users.user_id | SET NULL |
| `fk_pv_reviewer` | patch_verifications.reviewer_id | users.user_id | RESTRICT |
| `fk_pv_ticket` | patch_verifications.ticket_id | vuln_tickets.ticket_id | RESTRICT |
| `fk_users_department` | users.department_id | departments.department_id | RESTRICT |
| `fk_ticket_analyst` | vuln_tickets.assigned_analyst_id | users.user_id | RESTRICT |
| `fk_ticket_asset` | vuln_tickets.asset_id | assets.asset_id | RESTRICT |
| `fk_ticket_cve` | vuln_tickets.cve_id | cve_records.cve_id | RESTRICT |

### Views, routines, triggers and events

- **Views (7)**: `v_asset_exposure`, `v_audit_trail`, `v_cve_catalog`, `v_cves_pending_sync`, `v_department_risk`, `v_ticket_board`, `v_user_directory`
- **Functions (5)**: `fn_can_manage_asset`, `fn_is_sla_breached`, `fn_risk_index`, `fn_severity_from_cvss`, `fn_sla_days`
- **Procedures (12)**: `sp_blast_radius`, `sp_owner_assets`, `sp_owner_blast_radius`, `sp_owner_summary`, `sp_owner_tickets`, `sp_register_asset`, `sp_retire_asset`, `sp_review_patch`, `sp_sla_sweep`, `sp_submit_patch`, `sp_triage_ticket`, `sp_update_asset`
- **Triggers (11)**: `trg_audit_bd_immutable`, `trg_audit_bu_immutable`, `trg_cve_bi_severity`, `trg_cve_bu_severity`, `trg_dep_bi_validate`, `trg_dep_bu_validate`, `trg_ticket_ai_audit`, `trg_ticket_au_audit`, `trg_ticket_bi_validate`, `trg_ticket_bu_lifecycle`, `trg_users_bu_guard`
- **Events (1)**: `ev_sla_sweep`

## PostgreSQL 16 + pgvector (`zerodayhub_vectors`)

### `cve_threat_vectors`

Derived semantic index: one row per CVE that has advisory text.

| Column | Type | Null | Default | Description |
|---|---|---|---|---|
| `cve_id` | character varying | NO |  | Logical foreign key to MySQL cve_records.cve_id (CHECK format). |
| `advisory_text` | text | NO |  | Text that is embedded together with the title and CWE name. |
| `exploit_summary` | text | YES |  | How the flaw is exploited (also embedded). |
| `remediation_playbook` | text | YES |  | Fix steps (shown, not embedded). |
| `metadata` | jsonb | NO | '{}'::jsonb | JSONB filters: severity, cvss, cwe, vendor, product, tags. |
| `embedding` | vector(384) | NO |  | 384-dimension L2-normalised sentence embedding. |
| `embedding_model` | character varying | NO |  | Model that produced the vector; searches only compare like with like. |
| `content_hash` | character | NO |  | SHA-256 of the embedded text; unchanged text is never re-embedded. |
| `search_tsv` | tsvector | YES |  | Generated tsvector for hybrid full-text ranking. |
| `created_at` | timestamp with time zone | NO | now() | Creation time. |
| `updated_at` | timestamp with time zone | NO | now() | Touched by trigger on every update. |

Indexes:

- `cve_threat_vectors_pkey`: `btree (cve_id)`
- `idx_ctv_embedding_hnsw`: `hnsw (embedding vector_cosine_ops) WITH (m='16', ef_construction='64')`
- `idx_ctv_metadata_gin`: `gin (metadata jsonb_path_ops)`
- `idx_ctv_model`: `btree (embedding_model)`
- `idx_ctv_severity`: `btree (((metadata ->> 'severity'::text)))`
- `idx_ctv_tsv_gin`: `gin (search_tsv)`

Functions: `fn_ctv_touch`, `fn_hybrid_search`, `fn_semantic_search`; view `v_vector_stats`.

