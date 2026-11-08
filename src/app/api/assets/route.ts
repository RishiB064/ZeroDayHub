import { route } from "@/lib/errors";
import { json, readJson } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { createAsset, listAssets } from "@/lib/services/assets";
import { assetCreateSchema } from "@/lib/validation";

export const dynamic = "force-dynamic";

export const GET = route(async () => {
  const user = await requireUser("tickets:read");
  return json({ assets: await listAssets(user) });
});

export const POST = route(async (req: Request) => {
  const user = await requireUser("assets:manage");
  const body = assetCreateSchema.parse(await readJson(req));
  return json(await createAsset(user, body), 201);
});
