import { route } from "@/lib/errors";
import { json, qs, readJson } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { listTickets, triageTicket } from "@/lib/services/tickets";
import { ticketCreateSchema } from "@/lib/validation";

export const dynamic = "force-dynamic";

export const GET = route(async (req: Request) => {
  const user = await requireUser("tickets:read");
  const tickets = await listTickets(user, {
    status: qs(req, "status"),
    severity: qs(req, "severity"),
    environment: qs(req, "environment"),
    breached: qs(req, "breached") === "1",
    q: qs(req, "q"),
  });
  return json({ tickets });
});

// Analyst/Admin: triage a new ticket (stored procedure sp_triage_ticket sets the SLA)
export const POST = route(async (req: Request) => {
  const user = await requireUser("tickets:triage");
  const body = ticketCreateSchema.parse(await readJson(req));
  return json(await triageTicket(user, body.assetId, body.cveId, body.analystId), 201);
});
