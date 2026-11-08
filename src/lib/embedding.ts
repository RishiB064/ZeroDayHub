import { createHash } from "node:crypto";

/**
 * Embedding service.
 *
 * What is embedded : title + CWE name + advisory text + exploit summary of a CVE
 *                    (the "what is this weakness" text - not the remediation steps,
 *                    which are returned alongside matches instead).
 * Model            : Xenova/all-MiniLM-L6-v2 (sentence-transformers MiniLM, ONNX build)
 *                    run in-process with @huggingface/transformers - no API key, no cost.
 * Dimension        : 384, mean-pooled and L2-normalised, so cosine distance is meaningful.
 *
 * EMBEDDING_PROVIDER=hash is an OFFLINE fallback (feature-hashed bag of words) used for
 * tests and for machines that cannot download the model. Because its vectors live in a
 * different space, every row stores `embedding_model` and searches only compare vectors
 * produced by the same model.
 */
export const EMBEDDING_DIM = 384;

const g = globalThis as unknown as { __zdhExtractor?: Promise<(t: string, o: object) => Promise<{ data: Float32Array }>> };

export function embeddingProvider(): "transformers" | "hash" {
  return (process.env.EMBEDDING_PROVIDER ?? "transformers").toLowerCase() === "hash" ? "hash" : "transformers";
}

export function embeddingModelName(): string {
  return embeddingProvider() === "hash" ? "hash-384-v1" : process.env.EMBEDDING_MODEL ?? "Xenova/all-MiniLM-L6-v2";
}

export function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

export interface EmbeddableDoc {
  title: string;
  cweName?: string | null;
  advisoryText: string;
  exploitSummary?: string | null;
}

export function buildEmbeddingText(d: EmbeddableDoc): string {
  return [d.title, d.cweName, d.advisoryText, d.exploitSummary]
    .filter((p): p is string => !!p && p.trim().length > 0)
    .join(". ");
}

// ---------------------------------------------------------------- transformers

async function getExtractor() {
  if (!g.__zdhExtractor) {
    g.__zdhExtractor = (async () => {
      const { pipeline } = await import("@huggingface/transformers");
      const extractor = await pipeline("feature-extraction", embeddingModelName());
      return extractor as unknown as (t: string, o: object) => Promise<{ data: Float32Array }>;
    })();
    g.__zdhExtractor.catch(() => {
      g.__zdhExtractor = undefined; // allow a retry after a failed download
    });
  }
  return g.__zdhExtractor;
}

// ------------------------------------------------------------------ hash (offline)

const STOP = new Set(
  "a an and are as at be by for from has have in into is it its of on or that the their this to was were which while with can may will when who any all each than then them they over under via not no".split(" "),
);

function stem(w: string): string {
  return w.replace(/(ing|ed|es|s|ly)$/i, (m, _g, off) => (off >= 4 ? "" : m));
}

function fnv1a(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function hashEmbed(text: string): number[] {
  const tokens = (text.toLowerCase().match(/[a-z0-9]+/g) ?? []).filter((t) => !STOP.has(t)).map(stem);
  const vec = new Float64Array(EMBEDDING_DIM);
  const add = (feature: string, weight: number) => {
    const h = fnv1a(feature);
    vec[h % EMBEDDING_DIM] += (h & 0x80000000 ? -1 : 1) * weight;
  };
  tokens.forEach((t, i) => {
    add(t, 1);
    if (i > 0) add(`${tokens[i - 1]}_${t}`, 0.6);
  });
  let norm = 0;
  for (const x of vec) norm += x * x;
  norm = Math.sqrt(norm) || 1;
  return Array.from(vec, (x) => x / norm);
}

// ---------------------------------------------------------------------- public API

export async function embedText(text: string): Promise<number[]> {
  const clean = text.trim();
  if (!clean) throw new Error("Cannot embed empty text");
  if (embeddingProvider() === "hash") return hashEmbed(clean);
  const extractor = await getExtractor();
  const out = await extractor(clean, { pooling: "mean", normalize: true });
  const vec = Array.from(out.data);
  if (vec.length !== EMBEDDING_DIM) {
    throw new Error(`Model returned ${vec.length} dimensions, expected ${EMBEDDING_DIM}`);
  }
  return vec;
}
