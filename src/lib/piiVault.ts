import { createHash } from "crypto";
import { isFeatureFlagEnabled } from "@/shared/utils/featureFlags";

const memoryFallback = new Map<string, string>();
const VAULT_TOKEN_RE = /\[VAULT_[A-Z_]+_[a-f0-9]{12}\]/g;

export function isVaultEnabled(): boolean {
  try {
    return isFeatureFlagEnabled("PII_REDACTION_ENABLED_VAULT");
  } catch {
    return process.env.PII_REDACTION_ENABLED_VAULT === "true" || process.env.PII_REDACTION_ENABLED_VAULT === "1";
  }
}

function hashValue(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 12);
}

export function vaultStore(value: string, type: string): string {
  const h = hashValue(`${type}:${value}`);
  const token = `[VAULT_${type.toUpperCase()}_${h}]`;
  try {
    const { getDbInstance } = require("@/lib/db/core") as typeof import("@/lib/db/core");
    const db = getDbInstance();
    db.prepare(
      "INSERT OR IGNORE INTO pii_vault (token, original, type, hash, created_at) VALUES (?,?,?,?,?)"
    ).run(token, value, type, h, new Date().toISOString());
  } catch {
    if (!memoryFallback.has(token)) memoryFallback.set(token, value);
  }
  return token;
}

export function vaultRestoreText(text: string): string {
  if (!text || typeof text !== "string" || text.indexOf("[VAULT_") === -1) return text;
  return text.replace(VAULT_TOKEN_RE, (m) => {
    try {
      const { getDbInstance } = require("@/lib/db/core") as typeof import("@/lib/db/core");
      const db = getDbInstance();
      const row = db.prepare("SELECT original FROM pii_vault WHERE token = ?").get(m) as { original: string } | undefined;
      if (row?.original) return `${row.original} [OFUSCATED]`;
    } catch {}
    const v = memoryFallback.get(m);
    if (v) return `${v} [OFUSCATED]`;
    return m;
  });
}

const VAULT_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  { name: "email", regex: /(?<=^|[^A-Za-z0-9])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?=$|[^A-Za-z0-9])/g },
  { name: "ssn", regex: /(?<=^|[^A-Za-z0-9])\d{3}-\d{2}-\d{4}(?=$|[^A-Za-z0-9])/g },
  { name: "credit_card", regex: /(?<=^|[^A-Za-z0-9])(?:\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{4}[-\s]?\d{6}[-\s]?\d{4,5})(?=$|[^A-Za-z0-9])/g },
  { name: "phone_us", regex: /(?<=^|[^A-Za-z0-9])(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?=$|[^A-Za-z0-9])/g },
  { name: "phone_br", regex: /(?<=^|[^A-Za-z0-9])(?:\+?55[-.\s]?)?\(?\d{2}\)?[-.\s]?(?:9\d{4}|[2-5]\d{3})[-.\s]?\d{4}(?=$|[^A-Za-z0-9])/g },
  { name: "cpf", regex: /(?<=^|[^A-Za-z0-9])\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?=$|[^A-Za-z0-9])/g },
  { name: "cnpj", regex: /(?<=^|[^A-Za-z0-9])\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}(?=$|[^A-Za-z0-9])/g },
  { name: "ip_address", regex: /(?<=^|[^A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?=$|[^A-Za-z0-9])/g },
  { name: "aws_key", regex: /(?<=^|[^A-Za-z0-9])AKIA[0-9A-Z]{16}(?=$|[^A-Za-z0-9])/g },
  { name: "api_key_generic", regex: /(?<=^|[^A-Za-z0-9])(?:sk|pk|api|key|token)[_-][a-zA-Z0-9]{20,}(?=$|[^A-Za-z0-9])/gi },
];

export function vaultRedactText(text: string): { text: string; count: number } {
  if (!text || typeof text !== "string") return { text, count: 0 };
  let out = text;
  let count = 0;
  for (const p of VAULT_PATTERNS) {
    p.regex.lastIndex = 0;
    out = out.replace(p.regex, (m) => {
      count++;
      return vaultStore(m, p.name);
    });
  }
  return { text: out, count };
}

export function vaultRestoreObject(obj: unknown, depth = 0): unknown {
  if (depth > 100 || obj == null) return obj;
  if (typeof obj === "string") return vaultRestoreText(obj);
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) obj[i] = vaultRestoreObject(obj[i], depth + 1);
    return obj;
  }
  if (typeof obj === "object") {
    for (const k of Object.keys(obj as Record<string, unknown>)) {
      (obj as Record<string, unknown>)[k] = vaultRestoreObject((obj as Record<string, unknown>)[k], depth + 1);
    }
    return obj;
  }
  return obj;
}

export function clearVaultMemory(): void {
  memoryFallback.clear();
}
