export interface JwtParts {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
  raw: { header: string; payload: string; signature: string };
}

export interface JwtInspection extends JwtParts {
  issues: string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  isExpired?: boolean;
  expiresInSeconds?: number;
  summaryLines: string[];
}

function decodeBase64Url(segment: string): string {
  const padded = segment.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4;
  const withPad = pad ? padded + "=".repeat(4 - pad) : padded;
  return Buffer.from(withPad, "base64").toString("utf8");
}

function parseJson(segment: string, label: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(segment);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(`${label} is not a JSON object`);
    }
    return parsed as Record<string, unknown>;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid ${label}: ${msg}`);
  }
}

export function decodeJwt(token: string): JwtParts {
  const parts = token.trim().split(".");
  if (parts.length !== 3) {
    throw new Error("JWT must have exactly three dot-separated segments");
  }
  const [h, p, s] = parts;
  const headerJson = decodeBase64Url(h);
  const payloadJson = decodeBase64Url(p);
  return {
    header: parseJson(headerJson, "header"),
    payload: parseJson(payloadJson, "payload"),
    signature: s,
    raw: { header: h, payload: p, signature: s },
  };
}

function asUnixSeconds(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && /^\d+$/.test(value)) return parseInt(value, 10);
  return undefined;
}

export function inspectJwt(token: string, nowSeconds?: number): JwtInspection {
  const now = nowSeconds ?? Math.floor(Date.now() / 1000);
  const parts = decodeJwt(token);
  const issues: string[] = [];
  const summaryLines: string[] = [];

  const alg = parts.header.alg;
  if (alg === undefined) issues.push("header.alg is missing");
  else summaryLines.push(`alg: ${String(alg)}`);

  if (parts.header.typ !== undefined) {
    summaryLines.push(`typ: ${String(parts.header.typ)}`);
  }

  const exp = asUnixSeconds(parts.payload.exp);
  const nbf = asUnixSeconds(parts.payload.nbf);
  const iat = asUnixSeconds(parts.payload.iat);

  let isExpired: boolean | undefined;
  let expiresInSeconds: number | undefined;

  if (exp !== undefined) {
    isExpired = now >= exp;
    expiresInSeconds = exp - now;
    summaryLines.push(
      isExpired
        ? `expired ${Math.abs(expiresInSeconds)}s ago (exp=${exp})`
        : `expires in ${expiresInSeconds}s (exp=${exp})`
    );
    if (isExpired) issues.push("token is expired");
  } else {
    issues.push("payload.exp is missing");
  }

  if (nbf !== undefined && now < nbf) {
    issues.push(`token not valid until nbf=${nbf}`);
    summaryLines.push(`nbf in future (${nbf - now}s)`);
  }

  if (iat !== undefined) {
    summaryLines.push(`iat: ${iat}`);
  }

  const sub = parts.payload.sub;
  if (sub !== undefined) summaryLines.push(`sub: ${String(sub)}`);

  return {
    ...parts,
    issues,
    exp,
    nbf,
    iat,
    isExpired,
    expiresInSeconds,
    summaryLines,
  };
}
