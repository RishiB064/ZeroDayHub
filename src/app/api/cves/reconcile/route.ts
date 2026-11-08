import { route } from "@/lib/errors";
import { json } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { reconcile } from "@/lib/services/cves";

// Re-sync every PENDING/FAILED CVE and remove orphaned vectors
export const POST = route(async () => {
  const user = await requireUser("cves:write");
  return json(await reconcile(user));
});
