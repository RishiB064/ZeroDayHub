import { route } from "@/lib/errors";
import { json, parseId, readJson, type Ctx } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { patchUser } from "@/lib/services/admin";
import { userPatchSchema } from "@/lib/validation";

// Activate / deactivate / change role. The "last admin" rule is a MySQL trigger.
export const PATCH = route(async (req: Request, ctx: Ctx<{ id: string }>) => {
  const user = await requireUser("users:admin");
  const id = parseId((await ctx.params).id, "user id");
  return json(await patchUser(user, id, userPatchSchema.parse(await readJson(req))));
});
