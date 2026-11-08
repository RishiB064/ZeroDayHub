import { route } from "@/lib/errors";
import { json, type Ctx } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { resyncCve } from "@/lib/services/cves";
import { cveIdSchema } from "@/lib/validation";

// Retry the MySQL -> PostgreSQL copy for one CVE
export const POST = route(async (_req: Request, ctx: Ctx<{ id: string }>) => {
  const user = await requireUser("cves:write");
  return json(await resyncCve(user, cveIdSchema.parse((await ctx.params).id)));
});
