import { call, query, type Row } from "../db/mysql";
import type { SessionUser } from "../session";
import { ApiError } from "../errors";

export interface TicketFilters {
  status?: string;
  severity?: string;
  environment?: string;
  breached?: boolean;
  q?: string;
}

const ORDER = "FIELD(status, 'ESCALATED', 'OPEN', 'IN_PROGRESS', 'RESOLVED'), sla_deadline";

/**
 * Asset owners can only read through sp_owner_tickets (the procedure filters by owner inside
 * the database); analysts and admins read the whole board view.
 */
export async function listTickets(user: SessionUser, f: TicketFilters = {}): Promise<Row[]> {
  if (user.role === "Asset_Owner") {
    const rows = await call(user.role, "sp_owner_tickets", [user.id]);
    return rows.filter((r) =>
      (!f.status || r.status === f.status) &&
      (!f.severity || r.severity === f.severity) &&
      (!f.environment || r.environment === f.environment) &&
      (!f.breached || Number(r.sla_breached) === 1) &&
      (!f.q || `${r.hostname} ${r.cve_id} ${r.cve_title}`.toLowerCase().includes(f.q.toLowerCase())));
  }
  const where: string[] = [];
  const params: unknown[] = [];
  if (f.status) { where.push("status = ?"); params.push(f.status); }
  if (f.severity) { where.push("severity = ?"); params.push(f.severity); }
  if (f.environment) { where.push("environment = ?"); params.push(f.environment); }
  if (f.breached) where.push("sla_breached = 1");
  if (f.q) {
    where.push("(hostname LIKE ? OR cve_id LIKE ? OR cve_title LIKE ?)");
    params.push(`%${f.q}%`, `%${f.q}%`, `%${f.q}%`);
  }
  return query(user.role, `SELECT * FROM v_ticket_board ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY ${ORDER}`, params);
}

export async function triageTicket(user: SessionUser, assetId: number, cveId: string, analystId: number) {
  const rows = await call(user.role, "sp_triage_ticket", [assetId, cveId, analystId, user.id]);
  return { ticketId: Number(rows[0]?.ticket_id) };
}

export async function submitPatch(user: SessionUser, ticketId: number, commitHash: string) {
  const rows = await call(user.role, "sp_submit_patch", [ticketId, commitHash, user.id]);
  return rows[0];
}

export async function reviewPatch(user: SessionUser, ticketId: number, verdict: "VERIFIED" | "REJECTED", notes: string | null) {
  const rows = await call(user.role, "sp_review_patch", [ticketId, user.id, verdict, notes]);
  return rows[0];
}

export async function ticketTimeline(user: SessionUser, ticketId: number): Promise<Row[]> {
  if (user.role === "Asset_Owner") throw new ApiError(403, "Audit history is not available to asset owners.");
  return query(user.role, "SELECT * FROM v_audit_trail WHERE ticket_id = ? ORDER BY logged_at, log_id", [ticketId]);
}
