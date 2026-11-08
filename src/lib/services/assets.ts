import { call, query, type Row } from "../db/mysql";
import type { SessionUser } from "../session";
import { z } from "zod";
import { assetCreateSchema, assetUpdateSchema } from "../validation";

export type AssetCreate = z.infer<typeof assetCreateSchema>;
export type AssetUpdate = z.infer<typeof assetUpdateSchema>;

export async function listAssets(user: SessionUser): Promise<Row[]> {
  if (user.role === "Asset_Owner") return call(user.role, "sp_owner_assets", [user.id]);
  // analysts/admins: owner names come from the hash-free directory view
  return query(
    user.role,
    `SELECT a.asset_id, a.hostname, a.ip_address, a.environment, a.os_version, a.criticality,
            a.owner_id, d.full_name AS owner_name,
            (SELECT COUNT(*) FROM vuln_tickets t
              WHERE t.asset_id = a.asset_id AND t.status <> 'RESOLVED') AS open_tickets
       FROM assets a JOIN v_user_directory d ON d.user_id = a.owner_id
      ORDER BY a.environment, a.hostname`,
  );
}

export async function createAsset(user: SessionUser, input: AssetCreate) {
  const ownerId = user.role === "Admin" ? input.ownerId ?? user.id : user.id;
  const rows = await call(user.role, "sp_register_asset", [
    user.id, ownerId, input.hostname, input.ipAddress, input.environment, input.osVersion ?? "", input.criticality,
  ]);
  return { assetId: Number(rows[0]?.asset_id) };
}

export async function updateAsset(user: SessionUser, assetId: number, input: AssetUpdate) {
  await call(user.role, "sp_update_asset", [
    user.id, assetId, input.ipAddress, input.environment, input.osVersion ?? "", input.criticality,
  ]);
  return { assetId };
}

export async function deleteAsset(user: SessionUser, assetId: number) {
  await call(user.role, "sp_retire_asset", [user.id, assetId]);
  return { assetId };
}

/** Recursive-CTE blast radius. Owners go through the ownership-gated procedure. */
export async function blastRadius(user: SessionUser, assetId: number): Promise<Row[]> {
  if (user.role === "Asset_Owner") return call(user.role, "sp_owner_blast_radius", [user.id, assetId]);
  return call(user.role, "sp_blast_radius", [assetId]);
}

export async function getAsset(user: SessionUser, assetId: number): Promise<Row | undefined> {
  const all = await listAssets(user);
  return all.find((a) => Number(a.asset_id) === assetId);
}
