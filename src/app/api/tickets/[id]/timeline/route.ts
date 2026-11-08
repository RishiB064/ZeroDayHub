import { route } from "@/lib/errors";
import { json, parseId, type Ctx } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { ticketTimeline } from "@/lib/services/tickets";

export const dynamic = "force-dynamic";

export const GET = route(async (_req: Request, ctx: Ctx<{ id: string }>) => {
  const user = await requireUser("audit:read");
  const id = parseId((await ctx.params).id, "ticket id");
  return json({ events: await ticketTimeline(user, id) });
});
