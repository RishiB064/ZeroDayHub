import { route } from "@/lib/errors";
import { json } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { getDashboard } from "@/lib/services/dashboard";

export const dynamic = "force-dynamic";

export const GET = route(async () => {
  const user = await requireUser("dashboard");
  return json(await getDashboard(user));
});
