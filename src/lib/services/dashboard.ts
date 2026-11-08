import { call, query, type Row } from "../db/mysql";
import type { SessionUser } from "../session";
import { countVectors, vectorStats } from "./vectors";

export interface Dashboard {
  scope: "organisation" | "mine";
  kpis: {
    openTickets: number;
    escalated: number;
    breached: number;
    resolved: number;
    avgRisk: number;
    totalAssets?: number;
  };
  severityMix: { severity: string; n: number }[];
  upcoming: Row[];
  departmentRisk?: Row[];
  exposure?: Row[];
  pendingSync?: number;
  vectors?: { total: number; models: Row[] };
}

export async function getDashboard(user: SessionUser): Promise<Dashboard> {
  if (user.role === "Asset_Owner") {
    const [summary] = await call(user.role, "sp_owner_summary", [user.id]);
    const tickets = await call(user.role, "sp_owner_tickets", [user.id]);
    const open = tickets.filter((t) => t.status !== "RESOLVED");
    const mix = new Map<string, number>();
    open.forEach((t) => mix.set(String(t.severity), (mix.get(String(t.severity)) ?? 0) + 1));
    return {
      scope: "mine",
      kpis: {
        openTickets: Number(summary?.open_tickets ?? 0),
        escalated: Number(summary?.escalated_tickets ?? 0),
        breached: open.filter((t) => Number(t.sla_breached) === 1).length,
        resolved: Number(summary?.resolved_tickets ?? 0),
        avgRisk: Number(summary?.avg_open_risk ?? 0),
        totalAssets: Number(summary?.total_assets ?? 0),
      },
      severityMix: [...mix].map(([severity, n]) => ({ severity, n })),
      upcoming: open.slice(0, 6),
    };
  }

  const role = user.role;
  const [k] = await query(role, `
    SELECT SUM(status <> 'RESOLVED')              AS open_tickets,
           SUM(status = 'ESCALATED')              AS escalated,
           SUM(sla_breached)                      AS breached,
           SUM(status = 'RESOLVED')               AS resolved,
           COALESCE(ROUND(AVG(CASE WHEN status <> 'RESOLVED' THEN risk_index END), 2), 0) AS avg_risk
      FROM v_ticket_board`);
  const [assets] = await query(role, "SELECT COUNT(*) AS n FROM assets");
  const severityMix = await query<{ severity: string; n: number }>(
    role,
    `SELECT severity, COUNT(*) AS n FROM v_ticket_board WHERE status <> 'RESOLVED'
      GROUP BY severity ORDER BY FIELD(severity, 'Critical', 'High', 'Medium', 'Low')`);
  const upcoming = await query(
    role,
    `SELECT ticket_id, hostname, environment, cve_id, severity, status, sla_deadline, hours_to_sla, sla_breached, risk_index
       FROM v_ticket_board WHERE status <> 'RESOLVED' ORDER BY sla_deadline LIMIT 6`);
  const departmentRisk = await query(role, "SELECT * FROM v_department_risk ORDER BY risk_rank, department");
  const exposure = await query(role, "SELECT * FROM v_asset_exposure WHERE env_rank <= 3 ORDER BY FIELD(environment,'Production','Staging','Development'), env_rank, hostname");
  const [pending] = await query(role, "SELECT COUNT(*) AS n FROM v_cves_pending_sync");

  let vectors: Dashboard["vectors"];
  try {
    vectors = { total: await countVectors(role), models: await vectorStats(role) };
  } catch {
    vectors = undefined; // PostgreSQL unreachable: the rest of the dashboard still works
  }

  return {
    scope: "organisation",
    kpis: {
      openTickets: Number(k?.open_tickets ?? 0),
      escalated: Number(k?.escalated ?? 0),
      breached: Number(k?.breached ?? 0),
      resolved: Number(k?.resolved ?? 0),
      avgRisk: Number(k?.avg_risk ?? 0),
      totalAssets: Number(assets?.n ?? 0),
    },
    severityMix,
    upcoming,
    departmentRisk,
    exposure,
    pendingSync: Number(pending?.n ?? 0),
    vectors,
  };
}
