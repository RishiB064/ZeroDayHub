import { route } from "@/lib/errors";
import { json, qs, readJson } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { createCve, listCves } from "@/lib/services/cves";
import { cveCreateSchema } from "@/lib/validation";

export const dynamic = "force-dynamic";

export const GET = route(async (req: Request) => {
  const user = await requireUser("cves:read");
  return json({
    cves: await listCves(user, {
      q: qs(req, "q"), severity: qs(req, "severity"), sync: qs(req, "sync"),
      includeRetired: qs(req, "retired") === "1",
    }),
  });
});

// CREATE: MySQL row first, then embedding + pgvector row
export const POST = route(async (req: Request) => {
  const user = await requireUser("cves:write");
  const body = cveCreateSchema.parse(await readJson(req));
  return json(await createCve(user, body), 201);
});
