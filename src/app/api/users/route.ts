import { route } from "@/lib/errors";
import { json, readJson } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { createUser, listUsers } from "@/lib/services/admin";
import { userCreateSchema } from "@/lib/validation";

export const dynamic = "force-dynamic";

export const GET = route(async () => {
  const user = await requireUser("users:admin");
  return json({ users: await listUsers(user) });
});

export const POST = route(async (req: Request) => {
  const user = await requireUser("users:admin");
  return json(await createUser(user, userCreateSchema.parse(await readJson(req))), 201);
});
