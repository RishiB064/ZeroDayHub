import Link from "next/link";
import { notFound } from "next/navigation";
import { pageUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { getCve, listCwes } from "@/lib/services/cves";
import type { VectorMetadata } from "@/lib/services/vectors";
import CveForm from "@/components/CveForm";
import CveRowActions from "@/components/CveRowActions";
import { PageHead, SeverityBadge } from "@/components/ui";

export default async function CveDetail({ params }: { params: Promise<{ id: string }> }) {
  const user = await pageUser("cves:read");
  const id = decodeURIComponent((await params).id);
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) notFound();
  const detail = await getCve(user, id).catch(() => null);
  if (!detail) notFound();
  const { record: r, vector: v } = detail;
  const write = can(user.role, "cves:write");
  const cwes = write ? (await listCwes(user.role)).map((c) => ({ id: String(c.cwe_id), name: String(c.name) })) : [];
  const meta: VectorMetadata = v?.metadata ?? ({} as VectorMetadata);

  return (
    <>
      <PageHead title={String(r.cve_id)} sub={String(r.title)}>
        <Link className="btn secondary" href="/cves">Back</Link>
      </PageHead>
      <div className="card">
        <dl className="kv">
          <dt>Severity</dt><dd><SeverityBadge value={String(r.severity)} /> (CVSS {Number(r.cvss_score).toFixed(1)})</dd>
          <dt>Weakness</dt><dd>{r.cwe_id} · {r.cwe_name}</dd>
          {(meta.vendor || meta.product) && <><dt>Affects</dt><dd>{[meta.vendor, meta.product].filter(Boolean).join(" ")}</dd></>}
        </dl>
      </div>

      {v ? (
        <div className="card" style={{ marginTop: 14 }}>
          <h2>Advisory</h2>
          <p>{v.advisory_text}</p>
          {v.exploit_summary && <><h3>Exploit summary</h3><p>{v.exploit_summary}</p></>}
          {v.remediation_playbook && <><h3>Remediation playbook</h3><div className="playbook">{v.remediation_playbook}</div></>}
        </div>
      ) : (
        <div className="notice warn" style={{ marginTop: 14 }}>No advisory text is stored for this CVE yet.</div>
      )}

      {write && (
        <>
          <div style={{ margin: "16px 0" }}><CveRowActions cveId={String(r.cve_id)} canWrite redirect="/cves" /></div>
          <h3>Edit</h3>
          <CveForm editing cwes={cwes} initial={{
            cveId: String(r.cve_id), title: String(r.title), cweId: String(r.cwe_id), cvssScore: Number(r.cvss_score),
            publishedDate: String(r.published_date).slice(0, 10),
            advisoryText: v?.advisory_text ?? "", exploitSummary: v?.exploit_summary ?? "", remediationPlaybook: v?.remediation_playbook ?? "",
            vendor: String(meta.vendor ?? ""), product: String(meta.product ?? ""), tags: (meta.tags as string[] | undefined) ?? [],
          }} />
        </>
      )}
    </>
  );
}
