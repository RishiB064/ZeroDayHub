import Link from "next/link";
import { pageUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { listTickets } from "@/lib/services/tickets";
import FilterBar from "@/components/FilterBar";
import TicketActions from "@/components/TicketActions";
import { PageHead, SeverityBadge, StatusBadge, dueLabel, shortDate } from "@/components/ui";

type SP = Promise<Record<string, string | undefined>>;

export default async function TicketsPage({ searchParams }: { searchParams: SP }) {
  const user = await pageUser("tickets:read");
  const sp = await searchParams;
  const tickets = await listTickets(user, {
    status: sp.status, severity: sp.severity, environment: sp.environment, breached: sp.breached === "1", q: sp.q,
  });
  const isOwner = user.role === "Asset_Owner";

  return (
    <>
      <PageHead title="Tickets" sub={isOwner ? "Tickets on assets you own." : `${tickets.length} ticket(s) shown`}>
        {can(user.role, "tickets:triage") && <Link className="btn" href="/tickets/new">New ticket</Link>}
      </PageHead>
      <FilterBar filters={[
        { name: "q", label: "Search", type: "text", grow: true },
        { name: "status", label: "Status", type: "select", options: ["OPEN", "IN_PROGRESS", "ESCALATED", "RESOLVED"] },
      ]} />
      <div className="table-wrap">
        <table>
          <thead><tr><th>Vulnerability</th><th>Asset</th><th>Status</th><th>Due</th><th>Action</th></tr></thead>
          <tbody>
            {tickets.length === 0 && <tr><td colSpan={5} className="empty">No tickets match.</td></tr>}
            {tickets.map((t) => (
              <tr key={String(t.ticket_id)}>
                <td><Link href={`/cves/${t.cve_id}`}>{t.cve_id}</Link> <SeverityBadge value={String(t.severity)} /><div className="small">{t.cve_title}</div></td>
                <td><Link href={`/assets/${t.asset_id}`}>{t.hostname}</Link><div className="small">{t.environment}</div></td>
                <td><StatusBadge value={String(t.status)} /></td>
                <td>{t.status === "RESOLVED" ? <span className="small">resolved {shortDate(t.resolved_at)}</span> : <>{shortDate(t.sla_deadline)}<div className="small">{dueLabel(Number(t.hours_to_sla), Number(t.sla_breached) === 1)}</div></>}</td>
                <td>
                  <TicketActions
                    ticketId={Number(t.ticket_id)} status={String(t.status)}
                    canPatch={can(user.role, "tickets:patch")} canReview={can(user.role, "tickets:review")}
                    canTimeline={false}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
