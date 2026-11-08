import Link from "next/link";
import { pageUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { getDashboard } from "@/lib/services/dashboard";
import { listAudit } from "@/lib/services/admin";
import ReconcileButton from "@/components/ReconcileButton";
import { PageHead, SeverityBadge, shortDate } from "@/components/ui";

export default async function ReportsPage() {
  const user = await pageUser("audit:read");
  const [d, log] = await Promise.all([getDashboard(user), listAudit(user, { limit: 10 })]);

  return (
    <>
      <PageHead title="Reports" sub="Where the risk is, and what has happened recently.">
        {can(user.role, "cves:write") && <ReconcileButton />}
      </PageHead>

      <h2>Risk by department</h2>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Rank</th><th>Department</th><th className="num">Risk score</th></tr></thead>
          <tbody>
            {(d.departmentRisk ?? []).map((r) => (
              <tr key={String(r.department)}><td>{r.risk_rank}</td><td>{r.department}</td><td className="num">{Number(r.total_risk).toFixed(0)}</td></tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 style={{ marginTop: 26 }}>Most exposed assets</h2>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Asset</th><th>Environment</th><th>Criticality</th><th className="num">Open vulnerabilities</th></tr></thead>
          <tbody>
            {(d.exposure ?? []).map((e) => (
              <tr key={String(e.asset_id)}>
                <td><Link href={`/assets/${e.asset_id}`}>{e.hostname}</Link></td><td>{e.environment}</td>
                <td><SeverityBadge value={String(e.criticality)} /></td><td className="num">{e.active_vulns}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 style={{ marginTop: 26 }}>Recent activity</h2>
      <div className="table-wrap">
        <table>
          <thead><tr><th>When</th><th>Who</th><th>What</th></tr></thead>
          <tbody>
            {log.length === 0 && <tr><td colSpan={3} className="empty">No activity yet.</td></tr>}
            {log.map((r) => (
              <tr key={String(r.log_id)}><td className="mono">{shortDate(r.logged_at)}</td><td>{r.actor_name}</td><td>{r.log_message}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="sub" style={{ marginTop: 12 }}>
        {d.pendingSync ? `${d.pendingSync} advisory(ies) waiting to be added to the search index.` : "The search index is up to date."}
      </p>
    </>
  );
}
