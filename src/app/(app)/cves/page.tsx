import Link from "next/link";
import { pageUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { listCves } from "@/lib/services/cves";
import FilterBar from "@/components/FilterBar";
import { PageHead, SeverityBadge } from "@/components/ui";

type SP = Promise<Record<string, string | undefined>>;

export default async function CvesPage({ searchParams }: { searchParams: SP }) {
  const user = await pageUser("cves:read");
  const sp = await searchParams;
  const cves = await listCves(user, { q: sp.q });
  const write = can(user.role, "cves:write");

  return (
    <>
      <PageHead title="Advisories" sub="Known vulnerabilities (CVEs) and what to do about them.">
        {write && <Link className="btn" href="/cves/new">Add advisory</Link>}
      </PageHead>
      <FilterBar filters={[{ name: "q", label: "Search by title or CVE id", type: "text", grow: true }]} />
      <div className="table-wrap">
        <table>
          <thead><tr><th>CVE</th><th>Title</th><th>Severity</th></tr></thead>
          <tbody>
            {cves.length === 0 && <tr><td colSpan={3} className="empty">No advisories match.</td></tr>}
            {cves.map((c) => (
              <tr key={String(c.cve_id)}>
                <td><Link href={`/cves/${c.cve_id}`}>{c.cve_id}</Link></td>
                <td>{c.title}</td>
                <td><SeverityBadge value={String(c.severity)} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
