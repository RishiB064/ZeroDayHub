import Link from "next/link";
import { notFound } from "next/navigation";
import { pageUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { blastRadius, getAsset } from "@/lib/services/assets";
import AssetForm from "@/components/AssetForm";
import { PageHead, SeverityBadge } from "@/components/ui";

export default async function AssetDetail({ params }: { params: Promise<{ id: string }> }) {
  const user = await pageUser("tickets:read");
  const id = Number((await params).id);
  if (!Number.isInteger(id) || id <= 0) notFound();
  const asset = await getAsset(user, id);
  if (!asset) notFound();

  const radius = await blastRadius(user, id).catch(() => []);
  const canEdit = can(user.role, "assets:manage") && (user.role === "Admin" || Number(asset.owner_id) === user.id);

  return (
    <>
      <PageHead title={String(asset.hostname)} sub={`${asset.environment} · ${asset.ip_address}${asset.owner_name ? ` · owner ${asset.owner_name}` : ""}`}>
        <Link className="btn secondary" href="/assets">Back</Link>
      </PageHead>

      <div className="grid cols-2">
        <div className="card">
          <h2>Details</h2>
          <dl className="kv">
            <dt>Criticality</dt><dd><SeverityBadge value={String(asset.criticality)} /></dd>
            <dt>OS</dt><dd>{asset.os_version || "-"}</dd>
            <dt>Open tickets</dt><dd>{asset.open_tickets}</dd>
          </dl>
        </div>
        {canEdit && (
          <div className="card">
            <h2>Edit</h2>
            <AssetForm initial={{ assetId: id, ipAddress: String(asset.ip_address), environment: String(asset.environment), osVersion: String(asset.os_version ?? ""), criticality: String(asset.criticality) }} />
          </div>
        )}
      </div>

      <h3 style={{ marginTop: 22 }}>What else is exposed if this asset is compromised</h3>
      <p className="sub">Assets that depend on, or are reached through, this one.</p>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Depth</th><th>Asset</th><th>Environment</th><th>Criticality</th><th>Via</th><th className="num">Open vulns</th></tr></thead>
          <tbody>
            {radius.map((r) => (
              <tr key={String(r.asset_id)}>
                <td>{r.depth}</td>
                <td>{Number(r.depth) === 0 ? <strong>{r.hostname}</strong> : <Link href={`/assets/${r.asset_id}`}>{r.hostname}</Link>}</td>
                <td>{r.environment}</td>
                <td><SeverityBadge value={String(r.criticality)} /></td>
                <td>{r.via}</td>
                <td className="num">{r.open_tickets}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

    </>
  );
}
