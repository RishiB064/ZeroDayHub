import { route } from "@/lib/errors";
import { json, readJson } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { searchThreats } from "@/lib/services/search";
import { searchSchema } from "@/lib/validation";

// Semantic (pgvector) / hybrid search over CVE advisories, enriched from MySQL
export const POST = route(async (req: Request) => {
  const user = await requireUser("search");
  const body = searchSchema.parse(await readJson(req));
  return json(await searchThreats(user, body));
});
