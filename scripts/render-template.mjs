// Renders a *.tpl SQL file by replacing __NAME__ tokens with environment variables.
// Usage: node scripts/render-template.mjs <template> > rendered.sql
// Fails loudly when a referenced variable is missing, and escapes single
// quotes / backslashes so passwords are safe inside SQL string literals.
import { readFileSync } from "node:fs";

const file = process.argv[2];
if (!file) {
  console.error("usage: render-template.mjs <template>");
  process.exit(2);
}

const defaults = { APP_HOST: "localhost" };
const text = readFileSync(file, "utf8");
const missing = new Set();

const out = text.replace(/__([A-Z][A-Z0-9_]+)__/g, (_m, name) => {
  const value = process.env[name] ?? defaults[name];
  if (value === undefined || value === "") {
    missing.add(name);
    return `__${name}__`;
  }
  return String(value).replace(/\\/g, "\\\\").replace(/'/g, "''");
});

if (missing.size) {
  console.error(`Missing environment variables: ${[...missing].join(", ")}`);
  process.exit(1);
}
process.stdout.write(out);
