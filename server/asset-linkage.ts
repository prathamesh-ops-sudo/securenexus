const ASSET_REFERENCE_KEYS = [
  "id",
  "assetId",
  "asset_id",
  "hostname",
  "fqdn",
  "ip",
  "ipAddress",
  "ip_address",
  "name",
] as const;

function normalizeReference(value: string): string {
  return value.trim().toLocaleLowerCase();
}

function parseJsonValue(value: string): unknown {
  const trimmed = value.trim();
  if (!trimmed.startsWith("[") && !trimmed.startsWith("{")) {
    return value;
  }

  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    return value;
  }
}

export function normalizeAssetReferences(value: unknown): string[] {
  if (typeof value === "string") {
    const parsed = parseJsonValue(value);
    if (parsed !== value) {
      return normalizeAssetReferences(parsed);
    }
    const normalized = normalizeReference(value);
    return normalized ? [normalized] : [];
  }

  if (Array.isArray(value)) {
    return value.flatMap((item) => normalizeAssetReferences(item));
  }

  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return ASSET_REFERENCE_KEYS.flatMap((key) => normalizeAssetReferences(record[key]));
  }

  return [];
}

export function assetReferencesMatch(affectedAssets: unknown, identifiers: string[]): boolean {
  const references = new Set(normalizeAssetReferences(affectedAssets));
  return identifiers.some((identifier) => references.has(normalizeReference(identifier)));
}
