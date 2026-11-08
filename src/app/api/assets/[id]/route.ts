import { route } from "@/lib/errors";
import { json, parseId, readJson, type Ctx } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { deleteAsset, updateAsset } from "@/lib/services/assets";
import { assetUpdateSchema } from "@/lib/validation";

export const PUT = route(async (req: Request, ctx: Ctx<{ id: string }>) => {
  const user = await requireUser("assets:manage");
  const id = parseId((await ctx.params).id, "asset id");
  const body = assetUpdateSchema.parse(await readJson(req));
  return json(await updateAsset(user, id, body));
});

export const DELETE = route(async (_req: Request, ctx: Ctx<{ id: string }>) => {
  const user = await requireUser("assets:manage");
  const id = parseId((await ctx.params).id, "asset id");
  return json(await deleteAsset(user, id));
});
