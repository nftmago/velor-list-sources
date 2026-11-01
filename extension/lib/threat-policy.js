import { compileDomainRules, isPublicHostname, parseAbpDocumentList, parseDomainList, THREAT_RESOURCE_TYPES } from "./domain-rules.js";

export const MAX_FEED_BYTES = 50 * 1024 * 1024;
export const LIVE_RANGE_START = 30_000_000;
export const LIVE_RANGE_SIZE = 100_000;
// Order is attribution priority, independent of IDs retained for older diagnostics.
// `slot` fixes each feed's live rule range (stable across reordering; the
// validator asserts slots are unique and contiguous). `format` selects the
// parser; the default is a hosts/domain list. An optional feed (gated by
// `setting`) is lowest priority and compiles into its own static ruleset so it
// can be toggled without touching threat_protection.
export const THREAT_FEEDS = Object.freeze([
  { id: "certpl", slot: 0, name: "CERT Polska", category: "phishing", label: "CERT Polska phishing protection", url: "https://hole.cert.pl/domains/v2/domains.txt", file: "certpl-domains.txt", minimumDomains: 1_000, maximumDomains: 1_000_000, startId: 100_001 },
  { id: "urlhaus", slot: 1, name: "URLhaus", category: "malware", label: "URLhaus malware protection", url: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt", file: "urlhaus-hosts.txt", minimumDomains: 100, maximumDomains: 100_000, startId: 1 },
  { id: "phishing-filter", slot: 2, name: "malware-filter phishing protection", category: "phishing", label: "malware-filter phishing protection", url: "https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt", file: "phishing-filter-hosts.txt", minimumDomains: 1_000, maximumDomains: 250_000, startId: 200_001 },
  { id: "hagezi-fake", slot: 3, name: "HaGeZi Fake", category: "phishing", label: "HaGeZi scam and fake-site protection", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt", file: "hagezi-fake-domains.txt", minimumDomains: 1_000, maximumDomains: 250_000, startId: 300_001 },
  { id: "ubo-badware", slot: 6, name: "uBlock Origin Badware risks", category: "malware", label: "uBlock Origin badware and scam-site protection", url: "https://ublockorigin.github.io/uAssets/filters/badware.txt", file: "ubo-badware.txt", format: "abp-document", minimumDomains: 1_000, maximumDomains: 50_000, startId: 600_001 },
  { id: "hagezi-tif-mini", slot: 4, name: "HaGeZi Threat Intelligence", category: "malware", label: "HaGeZi malware protection", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt", file: "hagezi-tif-mini-domains.txt", minimumDomains: 10_000, maximumDomains: 1_000_000, startId: 400_001 },
  { id: "hagezi-gambling", slot: 5, name: "HaGeZi Gambling", category: "gambling", label: "HaGeZi gambling protection", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling.mini-onlydomains.txt", file: "hagezi-gambling-mini-domains.txt", metadataFile: "hagezi-gambling-mini-source.json", minimumDomains: 10_000, maximumDomains: 1_000_000, startId: 500_001, optional: true, setting: "blockGambling", ruleset: "gambling_protection" }
].map((feed) => Object.freeze({ ...feed, optional: feed.optional === true, ruleset: feed.ruleset || "threat_protection", format: feed.format || "domains",
  metadataFile: feed.metadataFile || `${feed.id}-source.json`, liveStartId: LIVE_RANGE_START + feed.slot * LIVE_RANGE_SIZE })));
const LIVE_RANGE_END = LIVE_RANGE_START + (Math.max(...THREAT_FEEDS.map((feed) => feed.slot)) + 1) * LIVE_RANGE_SIZE;

export const THREAT_RULESETS = Object.freeze([...new Set(THREAT_FEEDS.map((feed) => feed.ruleset))]);

export function enabledThreatFeeds(settings, feeds = THREAT_FEEDS) {
  return feeds.filter((feed) => !feed.setting || settings?.[feed.setting] === true);
}

export const PROTECTED_DOMAINS = Object.freeze([
  "google.com", "youtube.com", "github.com", "githubusercontent.com", "github.io", "gitlab.io",
  "microsoft.com", "live.com", "office.com", "sharepoint.com", "apple.com", "icloud.com", "amazon.com",
  "amazonaws.com", "cloudflare.com", "workers.dev", "pages.dev", "vercel.app", "netlify.app",
  "blogspot.com", "web.app", "firebaseapp.com", "appspot.com", "wikipedia.org", "mozilla.org",
  "brave.com", "facebook.com", "instagram.com", "whatsapp.com", "telegram.org", "discord.com", "dropbox.com"
]);

export function isProtectedDomain(domain) {
  return PROTECTED_DOMAINS.some((root) => root === domain || root.endsWith(`.${domain}`));
}

export function validateFeedCount(count, feed, previousCount = 0, allowJump = false) {
  if (!Number.isSafeInteger(count) || count < feed.minimumDomains || count > feed.maximumDomains) {
    throw new Error(`${feed.id}: ${count} domains outside expected ${feed.minimumDomains}–${feed.maximumDomains} range.`);
  }
  if (!allowJump && previousCount > 0 && (count < Math.floor(previousCount * 0.4) || count > Math.ceil(previousCount * 3))) {
    throw new Error(`${feed.id}: count changed from ${previousCount} to ${count}; needs attention.`);
  }
}

export function parseThreatFeed(text, feed) {
  return feed.format === "abp-document" ? parseAbpDocumentList(text) : parseDomainList(text);
}

export function validateFeedText(text, feed, previousCount = 0) {
  if (new TextEncoder().encode(text).byteLength > MAX_FEED_BYTES) throw new Error("Feed exceeds byte cap.");
  const domains = parseThreatFeed(text, feed);
  validateFeedCount(domains.length, feed, previousCount);
  return domains;
}

export function threatRulePriority(feed) {
  // Gambling sits below malware so an overlapping host is attributed to the threat feed.
  return feed.category === "phishing" ? 1_100 : feed.category === "malware" ? 1_000 : 900;
}

// Required feeds compile identically whether or not optional feeds are present:
// an optional feed never takes ownership from, or suppresses a child of, a
// required feed. Optional feeds still drop hosts the required feeds own or cover.
export function compileThreatFeeds(records, { live = false, feeds = THREAT_FEEDS } = {}) {
  const owners = new Map();
  const optional = new Set(feeds.filter((feed) => feed.optional).map((feed) => feed.id));
  const rejected = Object.fromEntries(feeds.map((feed) => [feed.id, { protected: 0, duplicate: 0, parent: 0 }]));
  for (const feed of feeds) {
    for (const domain of new Set(records[feed.id]?.domains || [])) {
      if (!isPublicHostname(domain) || domain !== domain.trim().toLowerCase()) continue;
      if (isProtectedDomain(domain)) { rejected[feed.id].protected++; continue; }
      if (owners.has(domain)) { rejected[feed.id].duplicate++; continue; }
      owners.set(domain, feed.id);
    }
  }
  const selected = Object.fromEntries(feeds.map((feed) => [feed.id, []]));
  const covers = (parentOwner, id) => parentOwner !== undefined && (!optional.has(parentOwner) || optional.has(id));
  for (const [domain, id] of owners) {
    const labels = domain.split(".");
    const redundant = labels.some((_, index) => index > 0 && covers(owners.get(labels.slice(index).join(".")), id));
    if (redundant) rejected[id].parent++;
    else selected[id].push(domain);
  }
  const rules = [];
  const sources = feeds.map((feed) => {
    const startId = live ? feed.liveStartId : feed.startId;
    // Chrome checks rules that only list domains one by one for every
    // request, so thousands of small chunks slowed every page load (about
    // 35 ms on a tracker-heavy page). Large rules cost one lookup each.
    const compiled = compileDomainRules(selected[feed.id], {
      startId, priority: threatRulePriority(feed), resourceTypes: THREAT_RESOURCE_TYPES, chunkSize: 25_000, maxRuleBytes: Infinity
    });
    if (compiled.length >= LIVE_RANGE_SIZE) throw new Error("Threat feed exhausted its rule ID range.");
    rules.push(...compiled);
    return { id: feed.id, name: feed.name, category: feed.category, domains: selected[feed.id].length,
      rules: compiled.length, ruleIdStart: startId, ruleIdEnd: startId + compiled.length - 1, rejected: rejected[feed.id] };
  });
  return { rules, sources };
}

export function isLiveThreatRuleId(id) {
  return Number.isSafeInteger(id) && id >= LIVE_RANGE_START && id < LIVE_RANGE_END;
}

export async function readThreatResponse(response, approvedUrl, maximumBytes = MAX_FEED_BYTES) {
  if (!response.ok) throw new Error(`Feed HTTP ${response.status}.`);
  if (response.url !== approvedUrl) throw new Error("Feed redirected outside its approved HTTPS source.");
  if (!/^text\/plain(?:\s*;|$)/i.test(response.headers.get("content-type") || "")) throw new Error("Feed is not text/plain.");
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > MAX_FEED_BYTES) throw new Error("Invalid byte cap.");
  if (Number(response.headers.get("content-length")) > maximumBytes) throw new Error("Feed exceeds byte cap.");
  if (!response.body?.getReader) throw new Error("Bounded streaming response unavailable.");
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let size = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximumBytes) { await reader.cancel().catch(() => undefined); throw new Error("Feed exceeds byte cap."); }
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  } finally { reader.releaseLock(); }
}
