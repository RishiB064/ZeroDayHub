import Link from "next/link";
import { pageUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { listAssets } from "@/lib/services/assets";
import { listOwners } from "@/lib/services/admin";
import AssetForm from "@/components/AssetForm";
import RetireAsset from "@/components/RetireAsset";
import { PageHead, SeverityBadge } from "@/components/ui";

export default async function AssetsPage() {
  const user = await pageUser("tickets:read");
  const assets = await listAssets(user);
  const manage = can(user.role, "assets:manage");
  const owners = user.role === "Admin" ? (await listOwners(user)).map((o) => ({ id: Number(o.user_id), label: `${o.full_name} (${o.department})` })) : undefined;

  return (
    <>
      <PageHead title="Assets" sub={user.role === "Asset_Owner" ? "Assets you own." : `${assets.length} assets in the inventory`} />
      <div className="table-wrap">
        <table>
          <thead><tr><th>Asset</th><th>Environment</th><th>Criticality</th>{user.role !== "Asset_Owner" && <th>Owner</th>}<th className="num">Open tickets</th>{manage && <th />}</tr></thead>
          <tbody>
            {assets.length === 0 && <tr><td colSpan={6} className="empty">No assets.</td></tr>}
            {assets.map((a) => (
              <tr key={String(a.asset_id)}>
                <td><Link href={`/assets/${a.asset_id}`}>{a.hostname}</Link></td>
                <td>{a.environment}</td>
                <td><SeverityBadge value={String(a.criticality)} /></td>
                {user.role !== "Asset_Owner" && <td>{a.owner_name}</td>}
                <td className="num">{a.open_tickets}</td>
                {manage && <td>{(user.role === "Admin" || Number(a.owner_id) === user.id || user.role === "Asset_Owner") && <RetireAsset assetId={Number(a.asset_id)} />}</td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {manage && (
        <div className="card" style={{ marginTop: 20 }}>
          <h2>Register an asset</h2>
          <AssetForm owners={owners} />
        </div>
      )}
    </>
  );
}
