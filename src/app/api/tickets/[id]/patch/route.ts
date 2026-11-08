import { route } from "@/lib/errors";
import { json, parseId, readJson, type Ctx } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { submitPatch } from "@/lib/services/tickets";
import { patchSubmitSchema } from "@/lib/validation";

// Asset owner attaches the remediation commit (ownership is re-checked inside MySQL)
export const POST = route(async (req: Request, ctx: Ctx<{ id: string }>) => {
  const user = await requireUser("tickets:patch");
  const id = parseId((await ctx.params).id, "ticket id");
  const body = patchSubmitSchema.parse(await readJson(req));
  return json({ ticket: await submitPatch(user, id, body.commitHash) });
});
