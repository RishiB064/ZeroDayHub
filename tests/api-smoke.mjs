// End-to-end API tests against a running server (npm run start / dev).
// Usage: BASE_URL=http://localhost:3000 node tests/api-smoke.mjs
const BASE = process.env.BASE_URL ?? "http://localhost:3000";
const PASSWORD = process.env.DEMO_PASSWORD ?? "ZeroDay@2026";
const ACCOUNTS = {
  admin: "vikram.admin@zerodayhub.io",
  analyst: "arjun.sec@zerodayhub.io",
  owner: "sneha.payments@zerodayhub.io",
};

let pass = 0, fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; failures.push(name); console.log(`  FAIL  ${name} ${detail}`); }
}

class Client {
  constructor() { this.cookies = new Map(); }
  header() { return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "); }
  store(res) {
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const [pair] = c.split(";");
      const i = pair.indexOf("=");
      const k = pair.slice(0, i), v = pair.slice(i + 1);
      if (v === "" || /expires=Thu, 01 Jan 1970/i.test(c)) this.cookies.delete(k); else this.cookies.set(k, v);
    }
  }
  async req(method, path, body, extra = {}) {
    const res = await fetch(BASE + path, {
      method, redirect: "manual",
      headers: { ...(body !== undefined ? { "Content-Type": "application/json" } : {}), Cookie: this.header(), ...extra },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    this.store(res);
    let data = null;
    const text = await res.text();
    try { data = JSON.parse(text); } catch { data = text; }
    return { status: res.status, data, res };
  }
  async login(email, password) {
    const csrf = (await this.req("GET", "/api/auth/csrf")).data.csrfToken;
    const res = await fetch(`${BASE}/api/auth/callback/credentials`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: this.header() },
      body: new URLSearchParams({ csrfToken: csrf, email, password, json: "true" }),
    });
    this.store(res);
    const session = (await this.req("GET", "/api/auth/session")).data;
    return session?.user ?? null;
  }
}

async function as(key) {
  const c = new Client();
  const user = await c.login(ACCOUNTS[key], PASSWORD);
  if (!user) throw new Error(`could not log in as ${key}`);
  return c;
}

const uniq = Date.now().toString().slice(-6);

console.log("\n== Authentication ==");
const anon = new Client();
check("anonymous GET /api/tickets -> 401", (await anon.req("GET", "/api/tickets")).status === 401);
check("anonymous page / redirects to login", [302, 307].includes((await anon.req("GET", "/")).status));
check("wrong password rejected", (await new Client().login(ACCOUNTS.analyst, "wrong-password-1")) === null);
check("unknown e-mail rejected", (await new Client().login("nobody@zerodayhub.io", PASSWORD)) === null);

const admin = await as("admin"), analyst = await as("analyst"), owner = await as("owner");
const me = (await owner.req("GET", "/api/auth/session")).data.user;
check("owner session has Asset_Owner role", me.role === "Asset_Owner");
check("session never exposes password hash", !JSON.stringify(me).includes("$2"));

console.log("\n== RBAC at the API layer ==");
check("owner cannot create a ticket (403)", (await owner.req("POST", "/api/tickets", { assetId: 1, cveId: "CVE-2026-0001", analystId: 2 })).status === 403);
check("owner cannot read audit log (403)", (await owner.req("GET", "/api/audit")).status === 403);
check("owner cannot list users (403)", (await owner.req("GET", "/api/users")).status === 403);
check("analyst cannot list users (403)", (await analyst.req("GET", "/api/users")).status === 403);
check("analyst cannot run SLA sweep (403)", (await analyst.req("POST", "/api/system/sla-sweep")).status === 403);
check("owner cannot write CVEs (403)", (await owner.req("POST", "/api/cves", {})).status === 403);
check("admin can list users and no hashes leak", await (async () => {
  const r = await admin.req("GET", "/api/users");
  return r.status === 200 && r.data.users.length >= 9 && !JSON.stringify(r.data).includes("password");
})());

console.log("\n== Owner data isolation (enforced in MySQL) ==");
const ownerTickets = (await owner.req("GET", "/api/tickets")).data.tickets;
const allTickets = (await analyst.req("GET", "/api/tickets")).data.tickets;
check("owner sees a subset of tickets", ownerTickets.length > 0 && ownerTickets.length < allTickets.length, `${ownerTickets.length}/${allTickets.length}`);
const ownerAssets = (await owner.req("GET", "/api/assets")).data.assets;
const allAssets = (await analyst.req("GET", "/api/assets")).data.assets;
check("owner sees only own assets", ownerAssets.length > 0 && ownerAssets.length < allAssets.length);
const foreign = allAssets.find((a) => !ownerAssets.some((o) => o.asset_id === a.asset_id));
check("owner blast radius on foreign asset is refused", [403, 400, 500].includes((await owner.req("GET", `/api/assets/${foreign.asset_id}/blast-radius`)).status));
check("owner cannot edit a foreign asset", (await owner.req("PUT", `/api/assets/${foreign.asset_id}`, { ipAddress: "10.9.9.9", environment: "Staging", criticality: "Low" })).status >= 400);
const foreignTicket = allTickets.find((t) => !ownerTickets.some((o) => o.ticket_id === t.ticket_id) && t.status !== "RESOLVED");
check("owner cannot submit a patch for a foreign ticket", (await owner.req("POST", `/api/tickets/${foreignTicket.ticket_id}/patch`, { commitHash: "abcdef1234" })).status >= 400);
check("owner timeline is forbidden", (await owner.req("GET", `/api/tickets/${ownerTickets[0].ticket_id}/timeline`)).status === 403);

console.log("\n== Ticket lifecycle (triage -> patch -> review) ==");
const assetForTicket = allAssets.find((a) => a.owner_name && ownerAssets.some((o) => o.asset_id === a.asset_id));
const cveList = (await analyst.req("GET", "/api/cves")).data.cves;
// pick a CVE not yet ticketed on that asset
const taken = new Set(allTickets.filter((t) => t.asset_id === assetForTicket.asset_id).map((t) => t.cve_id));
const freeCve = cveList.find((c) => !taken.has(c.cve_id));
const created = await analyst.req("POST", "/api/tickets", { assetId: assetForTicket.asset_id, cveId: freeCve.cve_id, analystId: 2 });
check("analyst triages a ticket (201)", created.status === 201 && created.data.ticketId > 0, JSON.stringify(created.data));
const tid = created.data.ticketId;
check("duplicate asset+CVE ticket is rejected (409)", (await analyst.req("POST", "/api/tickets", { assetId: assetForTicket.asset_id, cveId: freeCve.cve_id, analystId: 2 })).status === 409);
check("invalid commit hash rejected by validation (400/422)", [400, 422].includes((await owner.req("POST", `/api/tickets/${tid}/patch`, { commitHash: "zzz" })).status));
const sub = await owner.req("POST", `/api/tickets/${tid}/patch`, { commitHash: "a1b2c3d4e5f6" });
check("owner submits patch -> IN_PROGRESS", sub.status === 200, JSON.stringify(sub.data));
check("owner cannot review (403)", (await owner.req("POST", `/api/tickets/${tid}/review`, { verdict: "VERIFIED" })).status === 403);
const rej = await analyst.req("POST", `/api/tickets/${tid}/review`, { verdict: "REJECTED", notes: "tests failing" });
check("analyst rejects patch", rej.status === 200, JSON.stringify(rej.data));
await owner.req("POST", `/api/tickets/${tid}/patch`, { commitHash: "f6e5d4c3b2a1" });
const ver = await analyst.req("POST", `/api/tickets/${tid}/review`, { verdict: "VERIFIED" });
check("analyst verifies patch -> RESOLVED", ver.status === 200, JSON.stringify(ver.data));
const tl = await analyst.req("GET", `/api/tickets/${tid}/timeline`);
check("timeline recorded the whole lifecycle", tl.status === 200 && tl.data.events.length >= 4, `entries=${tl.data.events?.length}`);
check("re-reviewing a resolved ticket is refused", (await analyst.req("POST", `/api/tickets/${tid}/review`, { verdict: "VERIFIED" })).status >= 400);

console.log("\n== Assets CRUD ==");
const host = `smoke-${uniq}`;
const newAsset = await owner.req("POST", "/api/assets", { hostname: host, ipAddress: "10.77.0.5", environment: "Development", osVersion: "Ubuntu 24.04", criticality: "Low" });
check("owner registers an asset", newAsset.status === 201 && newAsset.data.assetId > 0, JSON.stringify(newAsset.data));
const aid = newAsset.data.assetId;
check("invalid IP rejected by the database CHECK", (await owner.req("POST", "/api/assets", { hostname: `bad-${uniq}`, ipAddress: "999.1.1.1", environment: "Development", criticality: "Low" })).status >= 400);
check("duplicate hostname rejected", (await owner.req("POST", "/api/assets", { hostname: host, ipAddress: "10.77.0.6", environment: "Development", criticality: "Low" })).status === 409);
check("owner updates own asset", (await owner.req("PUT", `/api/assets/${aid}`, { ipAddress: "10.77.0.9", environment: "Staging", osVersion: "Ubuntu 24.04", criticality: "Medium" })).status === 200);
check("owner retires own asset", (await owner.req("DELETE", `/api/assets/${aid}`)).status === 200);
const busy = ownerAssets.find((a) => Number(a.open_tickets) > 0);
check("asset with tickets cannot be retired", (await owner.req("DELETE", `/api/assets/${busy.asset_id}`)).status >= 400);

console.log("\n== Blast radius (recursive CTE) ==");
const br = await analyst.req("GET", `/api/assets/${allAssets[0].asset_id}/blast-radius`);
check("blast radius returns rows", br.status === 200 && (br.data.exposure ?? []).length >= 1, JSON.stringify(br.data).slice(0, 120));
const ids = (br.data.exposure ?? []).map((r) => r.asset_id);
check("no duplicate assets despite the dependency cycle", new Set(ids).size === ids.length);

console.log("\n== CVE CRUD with vector sync (MySQL + pgvector) ==");
const cveId = `CVE-2099-${uniq.padStart(5, "0")}`;
const cvePayload = {
  cveId, title: "Smoke test: path traversal in archive extractor", cweId: "CWE-22", cvssScore: 7.8, publishedDate: "2026-10-01",
  advisoryText: "The archive extractor does not normalise entry names so an attacker supplying a crafted zip can write files outside the target directory.",
  exploitSummary: "Craft a zip with ../ entries.", remediationPlaybook: "Upgrade the library.\nReject entries containing dot-dot segments.",
  vendor: "Acme", product: "Extractor", tags: ["zip", "traversal"],
};
const cc = await analyst.req("POST", "/api/cves", cvePayload);
check("analyst creates CVE -> vector SYNCED", cc.status === 201 && cc.data.sync.status === "SYNCED", JSON.stringify(cc.data));
const got = await analyst.req("GET", `/api/cves/${cveId}`);
check("CVE read returns MySQL record + pgvector document", got.status === 200 && got.data.record.severity === "High" && got.data.vector?.advisory_text?.includes("archive"), JSON.stringify(got.data).slice(0, 160));
check("severity derived from CVSS by a trigger (7.8 -> High)", got.data.record.severity === "High");
check("embedding model stored with the vector", !!got.data.vector?.embedding_model);
const found = await analyst.req("POST", "/api/search", { query: "write files outside the target directory using a crafted zip archive", k: 3, mode: "semantic" });
check("semantic search finds the new CVE", found.status === 200 && found.data.results.some((r) => r.cveId === cveId), JSON.stringify(found.data.results?.map((r) => r.cveId)));
const hyb = await analyst.req("POST", "/api/search", { query: "zip archive path traversal", k: 3, mode: "hybrid" });
check("hybrid search works", hyb.status === 200 && hyb.data.results.length > 0);
const upd = await analyst.req("PUT", `/api/cves/${cveId}`, { ...cvePayload, cvssScore: 9.6, advisoryText: cvePayload.advisoryText + " Exploitation requires no authentication." });
check("update re-embeds (SYNCED)", upd.status === 200 && upd.data.sync.status === "SYNCED", JSON.stringify(upd.data));
const got2 = await analyst.req("GET", `/api/cves/${cveId}`);
check("update changed severity to Critical and text in pgvector", got2.data.record.severity === "Critical" && got2.data.vector.advisory_text.includes("no authentication"));
check("invalid CVE id rejected (400)", (await analyst.req("GET", "/api/cves/not-a-cve")).status === 400);
check("CVSS out of range rejected", (await analyst.req("POST", "/api/cves", { ...cvePayload, cveId: "CVE-2099-99999", cvssScore: 11 })).status === 400);
const ownerSearch = await owner.req("POST", "/api/search", { query: "zip archive path traversal", k: 3 });
check("owner can search but sees no ticket counts", ownerSearch.status === 200 && ownerSearch.data.results.every((r) => r.openTickets === null));
const del = await analyst.req("DELETE", `/api/cves/${cveId}`);
check("delete removes MySQL row and vector", del.status === 200 && del.data.mode === "deleted" && del.data.vectorDeleted === true, JSON.stringify(del.data));
check("deleted CVE is gone (404)", (await analyst.req("GET", `/api/cves/${cveId}`)).status === 404);
// use a throw-away CVE + ticket so the seeded demo data is never retired by the test
const cve2 = `CVE-2099-${String(Number(uniq) + 1).padStart(5, "0")}`;
await analyst.req("POST", "/api/cves", { ...cvePayload, cveId: cve2, title: "Smoke test: second throw-away CVE" });
const freeAsset = allAssets.find((a) => a.environment === "Development") ?? allAssets[0];
const t2 = await analyst.req("POST", "/api/tickets", { assetId: freeAsset.asset_id, cveId: cve2, analystId: 2 });
const ret = await analyst.req("DELETE", `/api/cves/${cve2}`);
check("CVE with tickets is retired, not deleted", t2.status === 201 && ret.status === 200 && ret.data.mode === "retired", JSON.stringify(ret.data));
const rec = await analyst.req("POST", "/api/cves/reconcile");
check("reconcile job runs", rec.status === 200 && typeof rec.data.orphansRemoved === "number", JSON.stringify(rec.data));

console.log("\n== Dashboard, audit, admin ==");
const dashA = await admin.req("GET", "/api/dashboard");
const dashO = await owner.req("GET", "/api/dashboard");
check("admin dashboard is organisation-wide", dashA.data.dashboard?.scope === "organisation" || dashA.data.scope === "organisation", JSON.stringify(dashA.data).slice(0, 100));
check("owner dashboard is scoped to 'mine'", (dashO.data.dashboard?.scope ?? dashO.data.scope) === "mine");
const aud = await analyst.req("GET", "/api/audit");
check("audit log readable by analyst", aud.status === 200 && (aud.data.events ?? []).length > 0);
const sweep = await admin.req("POST", "/api/system/sla-sweep");
check("admin runs SLA sweep", sweep.status === 200 && typeof sweep.data.escalated === "number");
const nu = await admin.req("POST", "/api/users", { fullName: "Smoke Tester", email: `smoke${uniq}@zerodayhub.io`, password: "Smoke-Test-2026", role: "Asset_Owner", departmentId: 1 });
check("admin creates a user (password hashed by the app)", nu.status === 201, JSON.stringify(nu.data));
check("new user can log in", !!(await new Client().login(`smoke${uniq}@zerodayhub.io`, "Smoke-Test-2026")));
check("weak password rejected", (await admin.req("POST", "/api/users", { fullName: "Weak One", email: `weak${uniq}@zerodayhub.io`, password: "short", role: "Asset_Owner", departmentId: 1 })).status === 400);
const dis = await admin.req("PATCH", `/api/users/${nu.data.userId}`, { isActive: false });
check("admin deactivates the user", dis.status === 200);
check("deactivated user cannot log in", (await new Client().login(`smoke${uniq}@zerodayhub.io`, "Smoke-Test-2026")) === null);
const users = (await admin.req("GET", "/api/users")).data.users;
const adminsActive = users.filter((u) => u.role === "Admin" && Number(u.is_active));
if (adminsActive.length === 1) {
  check("last-admin guard trigger blocks deactivation", (await admin.req("PATCH", `/api/users/${adminsActive[0].user_id}`, { isActive: false })).status >= 400);
}

console.log("\n== Lockout ==");
const lockEmail = `smoke${uniq}@zerodayhub.io`;
// account is deactivated, so use the owner account of a dedicated new user
const lu = await admin.req("POST", "/api/users", { fullName: "Lock Tester", email: `lock${uniq}@zerodayhub.io`, password: "Lock-Test-2026", role: "Asset_Owner", departmentId: 1 });
for (let i = 0; i < 5; i++) await new Client().login(`lock${uniq}@zerodayhub.io`, "bad-password-x");
check("account locks after 5 failures (even with the right password)", (await new Client().login(`lock${uniq}@zerodayhub.io`, "Lock-Test-2026")) === null);
void lockEmail; void lu;

console.log("\n== Security headers ==");
const h = await fetch(BASE + "/login");
check("X-Frame-Options / CSP style headers present", !!h.headers.get("x-frame-options") || !!h.headers.get("content-security-policy"));
check("no X-Powered-By header", !h.headers.get("x-powered-by"));

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) { console.log("Failed:\n - " + failures.join("\n - ")); process.exit(1); }
