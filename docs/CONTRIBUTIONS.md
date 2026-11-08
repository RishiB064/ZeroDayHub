# Contributions, Git workflow and viva notes

## Split of work (from the course rubric)
| Member | Rubric items | Main files |
|---|---|---|
| **Saathvik** | 1 ER diagram, 2 relational schema, 3 DDL, 6 DML, 7 nested/correlated/recursive queries, 8 procedure/function/trigger/CTE | `db/mysql/*`, `docs/diagrams/er.dot`, `docs/DATA_DICTIONARY.md` |
| **Rishi** | 4 vector DB creation, 9 vector read/update/delete, 10 Next.js interface, 11 backend/API + DB integration, 12 authentication + RBAC in the database | `db/pg/*`, `db/mysql/06_roles.sql.tpl`, `src/**`, `tests/*`, `scripts/*` |
| Both | 5 and 13 testing, documentation, README | `docs/*`, `db/tests/*` |

## Suggested commit history (each person commits their own part under their own name)
```
Saathvik:  feat(db): schema DDL with constraints and indexes
           feat(db): functions, views
           feat(db): procedures incl. transactional sp_review_patch and recursive sp_blast_radius
           feat(db): triggers and SLA event
           feat(db): seed data and DML/query script
           docs: ER diagram and relational schema
Rishi:     feat(vector): pgvector schema, HNSW/GIN indexes, search functions
           feat(db): MySQL and PostgreSQL roles and grants
           feat(auth): next-auth credentials login, lockout, middleware
           feat(api): tickets, assets, CVE (MySQL+vector CRUD), search, audit, users
           feat(ui): dashboard, tickets, assets, CVEs, search, audit, admin
           test: db RBAC/integrity tests and API end-to-end tests
           docs: report, README, screenshots
```
Create the repository, add both collaborators, and commit in this order from your own machines so that `git log` shows individual contributions (the course asks for this).

## Viva: questions to be ready for
**Both:** why two databases? (derived vector index, source of truth in MySQL); what happens if PostgreSQL is down? (CVE is saved, status FAILED, reconcile later); how is a password stored? (bcrypt hash; CHECK rejects plain text).

**Saathvik:** why is severity stored although it is derivable? (controlled denormalisation, SLA FK, trigger keeps it right); why `ON DELETE RESTRICT` for tickets? (history must not vanish); explain `sp_review_patch` rollback; how does the recursive CTE avoid infinite loops? (visited-path check with `FIND_IN_SET`); what is 3NF here?

**Rishi:** what exactly is embedded and why not the playbook? why cosine? what is HNSW, what are m and ef_construction? what is RRF? how do you avoid re-embedding? how does RBAC work if the app is compromised? (DB accounts limit damage; owners have no table grants); what is the limitation of passing the owner id to procedures?
