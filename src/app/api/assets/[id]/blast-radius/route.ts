import { route } from "@/lib/errors";
import { json, parseId, type Ctx } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { blastRadius } from "@/lib/services/assets";

export const dynamic = "force-dynamic";

// Recursive CTE over asset_dependencies (sp_blast_radius)
export const GET = route(async (_req: Request, ctx: Ctx<{ id: string }>) => {
  const user = await requireUser("tickets:read");
  const id = parseId((await ctx.params).id, "asset id");
  return json({ exposure: await blastRadius(user, id) });
});
