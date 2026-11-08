import { route } from "@/lib/errors";
import { json, parseId, readJson, type Ctx } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { reviewPatch } from "@/lib/services/tickets";
import { reviewSchema } from "@/lib/validation";

// Analyst/Admin verifies or rejects a patch: one atomic transaction in sp_review_patch
export const POST = route(async (req: Request, ctx: Ctx<{ id: string }>) => {
  const user = await requireUser("tickets:review");
  const id = parseId((await ctx.params).id, "ticket id");
  const body = reviewSchema.parse(await readJson(req));
  return json({ ticket: await reviewPatch(user, id, body.verdict, body.notes ?? null) });
});
