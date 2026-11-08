import { z } from "zod";

/**
 * Application-layer validation (first, friendly line). The authoritative
 * validation is in the databases: CHECK constraints, FKs, triggers.
 */
export const cveIdSchema = z.string().trim().regex(/^CVE-\d{4}-\d{4,}$/, "must look like CVE-2026-12345");

export const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(150),
  password: z.string().min(1).max(200),
});

export const ticketCreateSchema = z.object({
  assetId: z.coerce.number().int().positive(),
  cveId: cveIdSchema,
  analystId: z.coerce.number().int().positive(),
});

export const patchSubmitSchema = z.object({
  commitHash: z.string().trim().regex(/^[0-9a-fA-F]{7,64}$/, "must be 7-64 hexadecimal characters"),
});

export const reviewSchema = z.object({
  verdict: z.enum(["VERIFIED", "REJECTED"]),
  notes: z.string().trim().max(500).optional().transform((v) => (v ? v : null)),
});

const environment = z.enum(["Production", "Staging", "Development"]);
const criticality = z.enum(["Low", "Medium", "High", "Critical"]);

export const assetCreateSchema = z.object({
  hostname: z.string().trim().min(2).max(120).regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/, "letters, digits, . _ - only"),
  ipAddress: z.string().trim().min(3).max(45),
  environment,
  osVersion: z.string().trim().max(80).optional().default(""),
  criticality,
  ownerId: z.coerce.number().int().positive().optional(),
});

export const assetUpdateSchema = assetCreateSchema.omit({ hostname: true, ownerId: true });

export const cveWriteSchema = z.object({
  title: z.string().trim().min(5).max(255),
  cweId: z.string().trim().regex(/^CWE-\d+$/, "must look like CWE-79"),
  cvssScore: z.coerce.number().min(0).max(10),
  publishedDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "use YYYY-MM-DD"),
  advisoryText: z.string().trim().min(20, "advisory text needs at least 20 characters").max(8000),
  exploitSummary: z.string().trim().max(4000).optional().default(""),
  remediationPlaybook: z.string().trim().max(8000).optional().default(""),
  vendor: z.string().trim().max(100).optional().default(""),
  product: z.string().trim().max(100).optional().default(""),
  tags: z.array(z.string().trim().min(1).max(40)).max(12).optional().default([]),
});
export const cveCreateSchema = cveWriteSchema.extend({ cveId: cveIdSchema });

export const searchSchema = z.object({
  query: z.string().trim().min(3, "describe the problem in at least 3 characters").max(1000),
  k: z.coerce.number().int().min(1).max(20).optional().default(5),
  mode: z.enum(["semantic", "hybrid"]).optional().default("semantic"),
  severity: z.enum(["Low", "Medium", "High", "Critical"]).optional(),
  minCvss: z.coerce.number().min(0).max(10).optional(),
  cwe: z.string().trim().regex(/^CWE-\d+$/).optional(),
});

export const userCreateSchema = z.object({
  fullName: z.string().trim().min(2).max(100),
  email: z.string().trim().toLowerCase().email().max(150),
  password: z
    .string()
    .min(10, "at least 10 characters")
    .max(100)
    .regex(/[A-Za-z]/, "needs a letter")
    .regex(/\d/, "needs a digit"),
  role: z.enum(["Security_Analyst", "Asset_Owner", "Admin"]),
  departmentId: z.coerce.number().int().positive(),
});

export const userPatchSchema = z.object({
  isActive: z.boolean().optional(),
  role: z.enum(["Security_Analyst", "Asset_Owner", "Admin"]).optional(),
});
