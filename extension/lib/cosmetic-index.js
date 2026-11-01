export const COSMETIC_BUCKET_COUNT = 128;
export const MAX_SITE_COSMETIC_SELECTORS = 1024;

function normalizedHostname(value) {
  return String(value || "").trim().toLowerCase().replace(/^\.+|\.+$/g, "");
}

export function cosmeticBucketFor(hostname, bucketCount = COSMETIC_BUCKET_COUNT) {
  const value = normalizedHostname(hostname);
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0) % bucketCount;
}

export function cosmeticBucketName(index) {
  return Number(index).toString(16).padStart(2, "0");
}

export function cosmeticHostnameCandidates(hostname) {
  const value = normalizedHostname(hostname);
  if (!value || value === "localhost" || /^\d+(?:\.\d+){3}$/.test(value)) return [];
  const labels = value.split(".").filter(Boolean);
  const candidates = [];
  for (let index = 0; index < labels.length - 1; index += 1) {
    candidates.push(labels.slice(index).join("."));
  }
  if (candidates.length <= 12) return candidates;
  return [...candidates.slice(0, 8), ...candidates.slice(-4)];
}

function domainMatches(hostname, domain) {
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

// A bucket document holds the ad lists' `domains` and, for annoyance buckets,
// one domain map per group under `groups`; only the named `groups` are read.
// Exceptions from any included section apply to all of them.
export function resolveCosmeticSelectors(hostname, bucketDocuments, maximum = MAX_SITE_COSMETIC_SELECTORS, groups = []) {
  const normalized = normalizedHostname(hostname);
  const candidates = cosmeticHostnameCandidates(normalized);
  const hides = new Map();
  const exceptions = new Set();

  for (const domain of candidates) {
    const bucket = cosmeticBucketFor(domain);
    const document = bucketDocuments instanceof Map
      ? bucketDocuments.get(bucket)
      : bucketDocuments?.[bucket] ?? bucketDocuments?.[cosmeticBucketName(bucket)];
    const entries = [document?.domains?.[domain], ...groups.map((group) => document?.groups?.[group]?.[domain])];
    for (const entry of entries) {
      if (!entry) continue;
      for (const selector of Array.isArray(entry.exceptions) ? entry.exceptions : []) {
        if (typeof selector === "string") exceptions.add(selector);
      }
      for (const item of Array.isArray(entry.hide) ? entry.hide : []) {
        if (!Array.isArray(item) || typeof item[0] !== "string") continue;
        const excludedDomains = Array.isArray(item[1]) ? item[1] : [];
        if (excludedDomains.some((excluded) => domainMatches(normalized, excluded))) continue;
        hides.set(item[0], item[0]);
      }
    }
  }

  return [...hides.keys()]
    .filter((selector) => !exceptions.has(selector))
    .sort()
    .slice(0, Math.max(0, Number(maximum) || 0));
}
