import { route } from "@/lib/errors";
import { json, qs } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { listAudit } from "@/lib/services/admin";

export const dynamic = "force-dynamic";

export const GET = route(async (req: Request) => {
  const user = await requireUser("audit:read");
  const ticket = qs(req, "ticketId");
  return json({
    events: await listAudit(user, {
      ticketId: ticket ? Number(ticket) : undefined,
      action: qs(req, "action"),
      limit: Number(qs(req, "limit") ?? 100),
    }),
  });
});
