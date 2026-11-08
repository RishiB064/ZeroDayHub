-- =====================================================================
-- File 07 - Seed data (run as root / the schema owner, after 06)
-- All demo accounts share the demo password  ZeroDay@2026
-- (stored below only as a salted bcrypt hash).
-- ALL CVE IDs, product names and vendors are FICTIONAL demo data
-- modelled on real vulnerability classes.
-- =====================================================================
USE zerodayhub_db;
SET @zdh_actor_id = 1;

INSERT INTO departments (name) VALUES
('Security Governance'), ('Threat Intel'), ('AppSec'), ('Cloud Infrastructure'),
('Core Payments'), ('Data Platform'), ('Customer Identity'), ('Corporate IT');

-- users (hash = bcrypt cost 10 of the demo password)
INSERT INTO users (full_name, email, password_hash, role, department_id) VALUES
('Vikram Rao',     'vikram.admin@zerodayhub.io',  '$2a$10$vJwmz.O6h7YA7pMlWKbtVOiI6b4ku23qWi.YS40oTAQOCgTgzhNM.', 'Admin',            1),
('Arjun Mehta',    'arjun.sec@zerodayhub.io',     '$2a$10$vJwmz.O6h7YA7pMlWKbtVOiI6b4ku23qWi.YS40oTAQOCgTgzhNM.', 'Security_Analyst', 2),
('Priya Nair',     'priya.sec@zerodayhub.io',     '$2a$10$vJwmz.O6h7YA7pMlWKbtVOiI6b4ku23qWi.YS40oTAQOCgTgzhNM.', 'Security_Analyst', 3),
('Meera Iyer',     'meera.sec@zerodayhub.io',     '$2a$10$vJwmz.O6h7YA7pMlWKbtVOiI6b4ku23qWi.YS40oTAQOCgTgzhNM.', 'Security_Analyst', 2),
('Rohan Sharma',   'rohan.devops@zerodayhub.io',  '$2a$10$vJwmz.O6h7YA7pMlWKbtVOiI6b4ku23qWi.YS40oTAQOCgTgzhNM.', 'Asset_Owner',      4),
('Sneha Patel',    'sneha.payments@zerodayhub.io','$2a$10$vJwmz.O6h7YA7pMlWKbtVOiI6b4ku23qWi.YS40oTAQOCgTgzhNM.', 'Asset_Owner',      5),
('Kabir Malhotra', 'kabir.data@zerodayhub.io',    '$2a$10$vJwmz.O6h7YA7pMlWKbtVOiI6b4ku23qWi.YS40oTAQOCgTgzhNM.', 'Asset_Owner',      6),
('Ananya Das',     'ananya.identity@zerodayhub.io','$2a$10$vJwmz.O6h7YA7pMlWKbtVOiI6b4ku23qWi.YS40oTAQOCgTgzhNM.','Asset_Owner',      7),
('Dev Kulkarni',   'dev.corpit@zerodayhub.io',    '$2a$10$vJwmz.O6h7YA7pMlWKbtVOiI6b4ku23qWi.YS40oTAQOCgTgzhNM.', 'Asset_Owner',      8);

UPDATE departments SET head_user_id = 1 WHERE name = 'Security Governance';
UPDATE departments SET head_user_id = 2 WHERE name = 'Threat Intel';
UPDATE departments SET head_user_id = 3 WHERE name = 'AppSec';
UPDATE departments SET head_user_id = 5 WHERE name = 'Cloud Infrastructure';
UPDATE departments SET head_user_id = 6 WHERE name = 'Core Payments';

INSERT INTO sla_policies (severity, sla_days) VALUES
('Low', 30), ('Medium', 14), ('High', 7), ('Critical', 3);

INSERT INTO cwe_catalog (cwe_id, name) VALUES
('CWE-415',  'Double Free'),
('CWE-89',   'SQL Injection'),
('CWE-125',  'Out-of-bounds Read'),
('CWE-269',  'Improper Privilege Management'),
('CWE-400',  'Uncontrolled Resource Consumption'),
('CWE-190',  'Integer Overflow or Wraparound'),
('CWE-79',   'Cross-site Scripting'),
('CWE-918',  'Server-Side Request Forgery'),
('CWE-22',   'Path Traversal'),
('CWE-502',  'Deserialization of Untrusted Data'),
('CWE-287',  'Improper Authentication'),
('CWE-611',  'XML External Entity Reference'),
('CWE-78',   'OS Command Injection'),
('CWE-416',  'Use After Free'),
('CWE-798',  'Use of Hard-coded Credentials'),
('CWE-362',  'Race Condition'),
('CWE-1321', 'Prototype Pollution'),
('CWE-295',  'Improper Certificate Validation'),
('CWE-352',  'Cross-Site Request Forgery'),
('CWE-601',  'Open Redirect');

INSERT INTO assets (hostname, ip_address, environment, os_version, criticality, owner_id) VALUES
('prod-pay-gw-01',     '10.120.4.15',  'Production',  'RHEL 9.2',          'Critical', 6),
('prod-auth-api-02',   '10.120.4.22',  'Production',  'Ubuntu 24.04 LTS',  'Critical', 8),
('prod-pay-db-01',     '10.120.4.31',  'Production',  'Debian 12',         'Critical', 6),
('prod-web-edge-01',   '10.120.2.10',  'Production',  'Ubuntu 22.04 LTS',  'High',     5),
('prod-data-lake-01',  '10.120.6.50',  'Production',  'RHEL 9.2',          'High',     7),
('prod-ledger-svc-01', '10.120.4.40',  'Production',  'Ubuntu 24.04 LTS',  'Critical', 6),
('stg-checkout-db',    '10.120.8.40',  'Staging',     'Debian 12',         'High',     6),
('stg-auth-api-01',    '10.120.8.22',  'Staging',     'Ubuntu 24.04 LTS',  'Medium',   8),
('stg-web-edge-01',    '10.120.9.10',  'Staging',     'Ubuntu 22.04 LTS',  'Medium',   5),
('dev-ml-worker-01',   '10.120.12.88', 'Development', 'Ubuntu 22.04 LTS',  'Low',      7),
('dev-sandbox-01',     '10.120.12.90', 'Development', 'Ubuntu 22.04 LTS',  'Low',      9),
('corp-vpn-gw-01',     '10.120.1.5',   'Production',  'Alpine 3.19',       'High',     9);

-- asset_id depends on depends_on_asset_id  (note the 3 <-> 6 cycle on purpose)
INSERT INTO asset_dependencies (asset_id, depends_on_asset_id, relationship) VALUES
(4, 2, 'CALLS'),            -- web edge  -> auth api
(4, 1, 'CALLS'),            -- web edge  -> payment gateway
(1, 2, 'CALLS'),            -- gateway   -> auth api
(1, 6, 'CALLS'),            -- gateway   -> ledger service
(1, 3, 'READS_DATA_FROM'),  -- gateway   -> payment db
(6, 3, 'READS_DATA_FROM'),  -- ledger    -> payment db
(3, 6, 'READS_DATA_FROM'),  -- payment db replicates from ledger (cycle 3 <-> 6)
(5, 3, 'READS_DATA_FROM'),  -- data lake -> payment db
(10, 5, 'READS_DATA_FROM'), -- ml worker -> data lake
(11, 10, 'CALLS'),          -- sandbox   -> ml worker
(9, 8, 'CALLS'),            -- stg web   -> stg auth
(9, 7, 'READS_DATA_FROM');  -- stg web   -> stg checkout db

INSERT INTO cve_records (cve_id, title, cwe_id, cvss_score, published_date) VALUES
('CVE-2026-1001', 'Meridian SSH daemon pre-auth double free allows remote code execution',        'CWE-415', 9.8, '2026-01-12'),
('CVE-2026-1002', 'Hollow ORM metadata call permits SQL injection through column aliases',        'CWE-89',  8.8, '2026-01-28'),
('CVE-2026-1003', 'Quill HTTP/3 server out-of-bounds read discloses process memory',              'CWE-125', 7.5, '2026-02-09'),
('CVE-2026-1004', 'Ketch kernel packet filter local privilege escalation',                        'CWE-269', 7.8, '2026-02-23'),
('CVE-2026-1005', 'Relay TLS socket handler resource exhaustion denial of service',               'CWE-400', 5.3, '2026-03-04'),
('CVE-2026-1006', 'Lattice image codec integer overflow leads to heap corruption',                'CWE-190', 9.1, '2026-03-17'),
('CVE-2026-1007', 'Pylon admin console stored cross-site scripting in the audit viewer',          'CWE-79',  6.1, '2026-03-30'),
('CVE-2026-1008', 'Corvid webhook service server-side request forgery reaches cloud metadata',    'CWE-918', 8.6, '2026-04-08'),
('CVE-2026-1009', 'Anvil file gateway path traversal exposes arbitrary files',                    'CWE-22',  7.5, '2026-04-19'),
('CVE-2026-1010', 'Vellum job runner unsafe deserialization enables remote code execution',       'CWE-502', 9.8, '2026-05-03'),
('CVE-2026-1011', 'Halcyon SSO broker authentication bypass via forged session token',            'CWE-287', 9.4, '2026-05-15'),
('CVE-2026-1012', 'Parchment document parser XML external entity expansion',                      'CWE-611', 7.1, '2026-05-27'),
('CVE-2026-1013', 'Lantern diagnostics endpoint OS command injection',                            'CWE-78',  9.0, '2026-06-06'),
('CVE-2026-1014', 'Finch browser engine use-after-free during frame teardown',                    'CWE-416', 8.8, '2026-06-18'),
('CVE-2026-1015', 'Warden endpoint agent ships with hard-coded service credentials',              'CWE-798', 8.1, '2026-06-29'),
('CVE-2026-1016', 'Ledgerline settlement service race condition allows double payout',            'CWE-362', 6.8, '2026-07-10'),
('CVE-2026-1017', 'Tundra configuration library prototype pollution via merge helper',            'CWE-1321',7.3, '2026-07-22'),
('CVE-2026-1018', 'Pigeon mail client skips certificate hostname validation',                     'CWE-295', 5.9, '2026-08-05'),
('CVE-2026-1019', 'Orchard customer portal missing CSRF protection on profile update',            'CWE-352', 4.3, '2026-08-19'),
('CVE-2026-1020', 'Cairn link service open redirect in login return parameter',                   'CWE-601', 3.7, '2026-09-02');
-- (severity is derived by trigger trg_cve_bi_severity; sync status stays PENDING until
--  `npm run db:seed-vectors` copies the advisories into PostgreSQL)

-- Tickets with hand-picked SLA deadlines (two are deliberately overdue)
INSERT INTO vuln_tickets (asset_id, cve_id, assigned_analyst_id, status, sla_deadline, remediation_commit_hash) VALUES
(1,  'CVE-2026-1001', 2, 'OPEN',        DATE_SUB(NOW(), INTERVAL 2 DAY),  NULL),             -- 1 overdue
(1,  'CVE-2026-1002', 3, 'IN_PROGRESS', DATE_ADD(NOW(), INTERVAL 5 DAY),  'a1b2c3d4e5f6'),   -- 2
(2,  'CVE-2026-1001', 2, 'OPEN',        DATE_ADD(NOW(), INTERVAL 2 DAY),  NULL),             -- 3
(3,  'CVE-2026-1002', 3, 'OPEN',        DATE_ADD(NOW(), INTERVAL 6 DAY),  NULL),             -- 4
(3,  'CVE-2026-1011', 4, 'OPEN',        DATE_ADD(NOW(), INTERVAL 1 DAY),  NULL),             -- 5
(4,  'CVE-2026-1003', 3, 'OPEN',        DATE_ADD(NOW(), INTERVAL 12 DAY), NULL),             -- 6
(4,  'CVE-2026-1007', 3, 'IN_PROGRESS', DATE_ADD(NOW(), INTERVAL 9 DAY),  'c0ffee1234'),     -- 7
(5,  'CVE-2026-1010', 4, 'OPEN',        DATE_ADD(NOW(), INTERVAL 2 DAY),  NULL),             -- 8
(6,  'CVE-2026-1016', 2, 'OPEN',        DATE_ADD(NOW(), INTERVAL 8 DAY),  NULL),             -- 9
(7,  'CVE-2026-1013', 4, 'OPEN',        DATE_SUB(NOW(), INTERVAL 1 DAY),  NULL),             -- 10 overdue
(9,  'CVE-2026-1018', 3, 'OPEN',        DATE_ADD(NOW(), INTERVAL 13 DAY), NULL),             -- 11
(12, 'CVE-2026-1006', 4, 'IN_PROGRESS', DATE_ADD(NOW(), INTERVAL 4 DAY),  'deadbeef01'),     -- 12
(10, 'CVE-2026-1005', 3, 'OPEN',        DATE_ADD(NOW(), INTERVAL 25 DAY), NULL);             -- 13

-- Tickets driven through the real workflow (procedures -> triggers -> audit log)
CALL sp_triage_ticket(2, 'CVE-2026-1004', 2, 2);          -- ticket 14
CALL sp_submit_patch(14, '9fceb02a1c', 8);                 -- owner of prod-auth-api-02
CALL sp_review_patch(14, 2, 'VERIFIED', 'Fix confirmed in release 4.2.1');

CALL sp_triage_ticket(8, 'CVE-2026-1011', 3, 3);          -- ticket 15
CALL sp_submit_patch(15, 'beadfeed42', 8);
CALL sp_review_patch(15, 3, 'VERIFIED', 'Token signing key rotated and verified');

CALL sp_triage_ticket(11, 'CVE-2026-1020', 4, 4);         -- ticket 16
CALL sp_submit_patch(16, '0badc0de99', 9);
CALL sp_review_patch(16, 4, 'REJECTED', 'Patch only covers one redirect parameter');
CALL sp_submit_patch(16, '1337c0ffee', 9);                 -- resubmitted after rejection

-- Scheduled sweep: escalates the two overdue tickets and writes audit entries
CALL sp_sla_sweep(@escalated_at_seed);
SELECT @escalated_at_seed AS tickets_escalated_by_sweep;
