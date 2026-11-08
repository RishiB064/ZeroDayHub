import { NextResponse } from "next/server";
import { ZodError } from "zod";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

const CHECK_MESSAGES: Record<string, string> = {
  chk_users_email: "That e-mail address is not valid.",
  chk_users_pwhash: "Passwords must be stored as a bcrypt hash.",
  chk_users_name: "Name is too short.",
  chk_assets_ip: "That is not a valid IPv4/IPv6 address.",
  chk_assets_hostname: "Hostname may only contain letters, digits, dots, dashes and underscores.",
  chk_cve_id_format: "CVE id must look like CVE-2026-12345.",
  chk_cvss_bounds: "CVSS score must be between 0.0 and 10.0.",
  chk_cve_title: "Title must be at least 5 characters.",
  chk_ticket_commit: "Commit hash must be 7-64 lowercase hex characters.",
  chk_ticket_resolved_has_commit: "A ticket cannot be resolved without a remediation commit.",
  chk_sla_days: "SLA days must be between 1 and 365.",
};

interface MysqlLikeError {
  code?: string;
  errno?: number;
  sqlState?: string;
  sqlMessage?: string;
  message: string;
}

/** Translate database errors into HTTP status + a safe, readable message. */
export function toApiError(err: unknown): ApiError {
  if (err instanceof ApiError) return err;
  if (err instanceof ZodError) {
    const first = err.issues[0];
    return new ApiError(400, `${first.path.join(".") || "input"}: ${first.message}`);
  }
  const e = err as MysqlLikeError;
  // MySQL
  switch (e.errno) {
    case 1644: // SIGNAL SQLSTATE '45000' raised by our triggers / procedures
      return new ApiError(/not allowed|only the asset owner/i.test(e.sqlMessage ?? "") ? 403 : 400, e.sqlMessage ?? "Rule violated");
    case 3819: {
      const name = /'([^']+)'/.exec(e.sqlMessage ?? "")?.[1]?.split(".").pop() ?? "";
      return new ApiError(400, CHECK_MESSAGES[name] ?? `Constraint violated: ${name}`);
    }
    case 1062:
      return new ApiError(409, "A record with that unique value already exists.");
    case 1452:
      return new ApiError(400, "Referenced record does not exist.");
    case 1451:
      return new ApiError(409, "Cannot delete: other records still reference this one.");
    case 1142:
    case 1143:
    case 1370:
    case 1044:
      return new ApiError(403, "The database denied this operation for your role.");
    case 1265:
    case 1366:
    case 1406:
    case 1292:
      return new ApiError(400, "One of the values has an invalid format or is too long.");
  }
  // PostgreSQL
  switch (e.code) {
    case "42501":
      return new ApiError(403, "The vector database denied this operation for your role.");
    case "23514":
      return new ApiError(400, `Constraint violated: ${(e as { constraint?: string }).constraint ?? "check"}`);
    case "23505":
      return new ApiError(409, "A vector record for that CVE already exists.");
  }
  console.error("[unhandled error]", err);
  return new ApiError(500, "Unexpected server error.");
}

export function errorResponse(err: unknown) {
  const apiErr = toApiError(err);
  return NextResponse.json({ error: apiErr.message }, { status: apiErr.status });
}

/** Wrap a route handler so every thrown error becomes a JSON response. */
export function route<A extends unknown[]>(
  fn: (...args: A) => Promise<Response>,
): (...args: A) => Promise<Response> {
  return async (...args: A) => {
    try {
      return await fn(...args);
    } catch (err) {
      return errorResponse(err);
    }
  };
}
