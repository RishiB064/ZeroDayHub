import { NextResponse } from "next/server";
import { ApiError } from "./errors";

export function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status });
}

export async function readJson(req: Request): Promise<unknown> {
  try {
    return await req.json();
  } catch {
    throw new ApiError(400, "Request body must be valid JSON.");
  }
}

export function parseId(value: string, label = "id"): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) throw new ApiError(400, `Invalid ${label}.`);
  return n;
}

export type Ctx<P extends Record<string, string>> = { params: Promise<P> };

/** Query-string helper: returns a trimmed string or undefined */
export function qs(req: Request, name: string): string | undefined {
  const v = new URL(req.url).searchParams.get(name);
  return v && v.trim() ? v.trim() : undefined;
}
