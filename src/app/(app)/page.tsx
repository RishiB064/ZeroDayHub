import Link from "next/link";
import { pageUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { listTickets } from "@/lib/services/tickets";
import TicketActions from "@/components/TicketActions";
import { PageHead, dueLabel, shortDate } from "@/components/ui";

const INTRO = {
  Asset_Owner: "Fix the vulnerabilities on your assets. Enter the commit hash of your fix and an analyst will verify it.",
  Security_Analyst: "Check the fixes owners have submitted, or raise a new ticket for an affected asset.",
  Admin: "Check submitted fixes, raise tickets and manage users.",
} as const;

export default async function HomePage() {
  const user = await pageUser("dashboard");
  const all = await listTickets(user, {});
  const open = all.filter((t) => t.status !== "RESOLVED");
  const isOwner = user.role === "Asset_Owner";
  // What this person has to do next
  const todo = isOwner
    ? open.filter((t) => t.status !== "IN_PROGRESS")
    : open.filter((t) => t.status === "IN_PROGRESS");
  const overdue = open.filter((t) => Number(t.sla_breached) === 1).length;

  return (
    <>
      <PageHead title={`Hello, ${user.name.split(" ")[0]}`} sub={INTRO[user.role]}>
        {can(user.role, "tickets:triage") && <Link className="btn" href="/tickets/new">New ticket</Link>}
        {can(user.role, "cves:write") && <Link className="btn secondary" href="/cves/new">Add advisory</Link>}
      </PageHead>

      <div className="steps">
        <span>Advisory added</span><i>&rarr;</i><span>Ticket raised</span><i>&rarr;</i>
        <span>Owner submits fix</span><i>&rarr;</i><span>Analyst verifies</span><i>&rarr;</i><span>Resolved</span>
      </div>

      <p className="todo-count">
        {todo.length === 0 ? "You're all caught up" : `${todo.length} ${todo.length === 1 ? "thing" : "things"} to do`}
        {overdue > 0 && <span className="small" style={{ fontSize: 15, fontWeight: 500, color: "var(--crit)", marginLeft: 12 }}>{overdue} overdue</span>}
      </p>

      <h2>{isOwner ? "Fix these" : "Review these"}</h2>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Vulnerability</th><th>Asset</th><th>Due</th><th>Action</th></tr></thead>
          <tbody>
            {todo.length === 0 && <tr><td colSpan={4} className="empty">Nothing to do right now.</td></tr>}
            {todo.map((t) => (
              <tr key={String(t.ticket_id)}>
                <td>
                  <Link href={`/cves/${t.cve_id}`}>{t.cve_id}</Link> <span className="small">{t.severity}</span>
                  <div className="small">{t.cve_title}</div>
                </td>
                <td>{t.hostname}<div className="small">{t.environment}</div></td>
                <td>{shortDate(t.sla_deadline)}<div className="small">{dueLabel(Number(t.hours_to_sla), Number(t.sla_breached) === 1)}</div></td>
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
      <p className="sub" style={{ marginTop: 12 }}><Link href="/tickets">See all tickets</Link></p>
    </>
  );
}
