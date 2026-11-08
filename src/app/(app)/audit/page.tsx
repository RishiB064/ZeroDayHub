import Link from "next/link";
import { pageUser } from "@/lib/session";
import { auditActions, listAudit } from "@/lib/services/admin";
import FilterBar from "@/components/FilterBar";
import { PageHead, shortDate } from "@/components/ui";

type SP = Promise<Record<string, string | undefined>>;

export default async function AuditPage({ searchParams }: { searchParams: SP }) {
  const user = await pageUser("audit:read");
  const sp = await searchParams;
  const ticketId = sp.ticket ? Number(sp.ticket) : undefined;
  const [rows, actions] = await Promise.all([
    listAudit(user, { ticketId: Number.isInteger(ticketId) ? ticketId : undefined, action: sp.action, limit: 200 }),
    auditActions(user),
  ]);
  return (
    <>
      <PageHead title="Audit log" sub="Append-only: database triggers write every entry and UPDATE/DELETE are blocked." />
      <FilterBar filters={[
        { name: "ticket", label: "Ticket #", type: "text" },
        { name: "action", label: "Action", type: "select", options: actions },
      ]} />
      <div className="table-wrap">
        <table>
          <thead><tr><th>When</th><th>Ticket</th><th>Asset</th><th>Action</th><th>Actor</th><th>Message</th></tr></thead>
          <tbody>
            {rows.length === 0 && <tr><td colSpan={6} className="empty">No entries.</td></tr>}
            {rows.map((r) => (
              <tr key={String(r.log_id)}>
                <td className="mono">{shortDate(r.logged_at)}</td>
                <td><Link href={`/audit?ticket=${r.ticket_id}`}>#{r.ticket_id}</Link></td>
                <td>{r.hostname} <span className="small">{r.cve_id}</span></td>
                <td><span className="tag">{r.action_type}</span></td>
                <td>{r.actor_name}</td>
                <td>{r.log_message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
