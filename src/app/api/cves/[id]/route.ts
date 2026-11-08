import { route, ApiError } from "@/lib/errors";
import { json, readJson, type Ctx } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { getCve, removeCve, updateCve } from "@/lib/services/cves";
import { cveIdSchema, cveWriteSchema } from "@/lib/validation";

export const dynamic = "force-dynamic";

export const GET = route(async (_req: Request, ctx: Ctx<{ id: string }>) => {
  const user = await requireUser("cves:read");
  const cveId = cveIdSchema.parse((await ctx.params).id);
  const detail = await getCve(user, cveId);
  if (!detail) throw new ApiError(404, "CVE not found");
  return json(detail);
});

export const PUT = route(async (req: Request, ctx: Ctx<{ id: string }>) => {
  const user = await requireUser("cves:write");
  const cveId = cveIdSchema.parse((await ctx.params).id);
  return json(await updateCve(user, cveId, cveWriteSchema.parse(await readJson(req))));
});

export const DELETE = route(async (_req: Request, ctx: Ctx<{ id: string }>) => {
  const user = await requireUser("cves:write");
  return json(await removeCve(user, cveIdSchema.parse((await ctx.params).id)));
});
