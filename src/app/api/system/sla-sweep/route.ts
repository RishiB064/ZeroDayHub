import { route } from "@/lib/errors";
import { json } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { slaSweep } from "@/lib/services/admin";

// Manual trigger of the same procedure that the MySQL event ev_sla_sweep runs every 5 minutes
export const POST = route(async () => {
  await requireUser("system:sweep");
  return json(await slaSweep());
});
