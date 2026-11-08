# ZeroDayHub

Vulnerability governance with semantic threat search.
**MySQL 8** (source of truth) + **PostgreSQL 16 / pgvector** (semantic index) + **Next.js 15**.
DBMS Experiential Learning, Level 3 Mini-Project, PES University.

All data in the seed is fictional. Full documentation is in [`docs/REPORT.md`](docs/REPORT.md).

## What you need
* Node.js 20+ (22 recommended)
* MySQL 8.0+ with the event scheduler allowed, and `mysql` client on the PATH
* PostgreSQL 16 with the **pgvector** extension installed (`CREATE EXTENSION vector` must work), and `psql` on the PATH
* An account that can create databases and users in each (MySQL `root`, PostgreSQL `postgres` is fine)

pgvector install hints: macOS `brew install pgvector`; Ubuntu/Debian `sudo apt install postgresql-16-pgvector`; Windows: use the pgvector release for your PostgreSQL version, or run PostgreSQL with Docker image `pgvector/pgvector:pg16`.

## Setup (about 5 minutes)

```bash
npm install

cp .env.example .env.local
#   edit .env.local:
#   - choose passwords for the six database accounts (they are CREATED for you)
#   - MYSQL_SETUP_USER / PG_SETUP_USER: an admin account for the one-time setup
#   - NEXTAUTH_SECRET: openssl rand -base64 32
#   - leave EMBEDDING_PROVIDER=transformers for real semantic search

npm run db:init            # creates both databases, roles, accounts, schema, seed data
npm run db:seed-vectors    # embeds the 20 advisories into pgvector (first run downloads ~90 MB model)
npm run dev                # http://localhost:3000
```

`db:init` is repeatable: it drops and recreates both databases. The credentials in `.env.local` are used by the app; the *setup* account is used only by `db:init`.

### Demo accounts (password `ZeroDay@2026`)
| Role | E-mail |
|---|---|
| Administrator | vikram.admin@zerodayhub.io |
| Security Analyst | arjun.sec@zerodayhub.io (also priya.sec@, meera.sec@) |
| Asset Owner | sneha.payments@zerodayhub.io (also rohan.devops@, kabir.data@, ananya.identity@, dev.corpit@, all @zerodayhub.io) |

Set `SHOW_DEMO_ACCOUNTS=false` to hide the hint on the login page, and change the password before any real use.

### Embedding providers
| `EMBEDDING_PROVIDER` | Behaviour |
|---|---|
| `transformers` (default) | Real sentence embeddings (all-MiniLM-L6-v2, 384-d), run locally, no API key. Needs internet once to download the model. |
| `hash` | Offline lexical fallback for machines without internet. Works, but matches words, not meaning. |

If you change the provider later, run `npm run db:seed-vectors` again (or use **Reconcile** on the CVE page); vectors from different models are never compared with each other.

## Try these
1. Sign in as the analyst, open **Threat search**, type *"attacker can run commands on the server through an upload"*, compare *Semantic* and *Hybrid*.
2. Open **CVE catalogue > Add CVE**: create one, watch it appear in search at once; edit its text (re-embedded); delete it (removed from both databases).
3. As owner `sneha.payments@...`, submit a patch hash on a ticket; as the analyst, **Verify** it; open **History**.
4. Open an asset with dependencies to see the **blast radius** (recursive CTE, cycle-safe).
5. As the owner, try `/audit` (denied). The same rules are enforced by the database accounts.

## Tests
```bash
npm run db:init && npm run db:seed-vectors
npm run test:db            # 58 database tests (integrity, audit, transaction, MySQL + PG RBAC)
npm run build && npm run start &
npm run test:api           # 64 end-to-end API tests (needs the server on :3000 and the demo seed)
```
Recorded results: `docs/test-results/`. The API test creates and removes its own throw-away rows.

## Project layout
```
db/mysql/        01 schema, 02 functions, 03 views, 04 procedures, 05 triggers+event,
                 06 roles (template), 07 seed, 08 DML + query showcase, 09 DDL demo
db/pg/           01 pgvector schema, 02 search functions, 03 roles (template)
db/seed/         advisories.json (fictional advisory text for the vectors)
db/tests/        run-db-tests.sh
scripts/         init-db.sh, seed-vectors.ts, render-template.mjs, gen-data-dictionary.py
src/app/         pages (Next.js App Router) and /api route handlers
src/lib/         db pools, auth, rbac, validation, embedding, services/
src/components/  client components
tests/           api-smoke.mjs
docs/            REPORT.md, DATA_DICTIONARY.md, CONTRIBUTIONS.md, diagrams/, screenshots/, test-results/
```

## Troubleshooting
* **Windows:** `npm run db:init` uses Node only (no bash, `mysql` or `psql` needed). `npm run test:db` needs bash (Git Bash); skip it if unavailable.
* **`extension "vector" is not available`**: install pgvector for your PostgreSQL version (see above).
* **`Access denied` right after `db:init`**: `.env.local` passwords must be the ones used when `db:init` ran; just run it again after editing.
* **`event_scheduler`**: `db:init` runs `SET GLOBAL event_scheduler = ON` (needs SUPER/SYSTEM_VARIABLES_ADMIN, which root has). Without it the 5-minute auto-escalation does not run; the admin "Run SLA sweep" button still works.
* **Search returns nothing / "different model" note**: run `npm run db:seed-vectors` after changing `EMBEDDING_PROVIDER`.
* **Model download blocked**: set `EMBEDDING_PROVIDER=hash`.
* **Account locked**: wait 10 minutes or restart the server (lockout is in memory).
