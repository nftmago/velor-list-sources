const HOSTS_LINE = /^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)(?:\s|$)/i;
const DOMAIN_LINE = /^([^\s#]+)(?:\s+#.*)?$/;
// ABP/uBO whole-host document blocks: `||host^` with no options, or only
// document/all/important and uBO's `reason=` annotation. Paths, wildcards,
// resource types, party and initiator/destination scopes are ignored.
const ABP_BLOCK_LINE = /^\|\|([^/^*$|\s]+)\^(?:\$(.*))?$/;
const ABP_EXCEPTION_LINE = /^@@\|\|([^/^*$|\s]+)/;
const ABP_DOCUMENT_OPTIONS = new Set(["doc", "document", "all", "important"]);

export const NETWORK_RESOURCE_TYPES = Object.freeze([
  "script",
  "image",
  "stylesheet",
  "font",
  "object",
  "media",
  "xmlhttprequest",
  "sub_frame",
  "ping",
  "websocket",
  "other"
]);

export const THREAT_RESOURCE_TYPES = Object.freeze([
  "main_frame",
  "sub_frame",
  "script",
  "image",
  "stylesheet",
  "font",
  "object",
  "media",
  "xmlhttprequest",
  "ping",
  "websocket",
  "other"
]);

export function isPublicHostname(value) {
  if (typeof value !== "string") return false;
  const hostname = value.trim().toLowerCase().replace(/^\.+|\.+$/g, "");
  if (!hostname || hostname.length > 253 || !hostname.includes(".")) return false;
  if (
    hostname === "localhost"
    || hostname.endsWith(".localhost")
    || hostname.endsWith(".local")
    || hostname.endsWith(".invalid")
    || hostname.endsWith(".test")
    || hostname.endsWith(".example")
  ) return false;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) return false;
  return hostname.split(".").every((label) => (
    label.length > 0
    && label.length <= 63
    && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  ));
}

export function parseDomainList(source) {
  if (typeof source !== "string") return [];
  const domains = [];
  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("!")) continue;
    const hostsMatch = line.match(HOSTS_LINE);
    const domainMatch = line.match(DOMAIN_LINE);
    const value = (hostsMatch?.[1] || domainMatch?.[1] || "")
      .toLowerCase()
      .replace(/^\.+|\.+$/g, "");
    if (isPublicHostname(value)) domains.push(value);
  }
  return [...new Set(domains)].sort();
}

// Any `@@||host` exception, whatever its tail, releases that host and its
// subdomains: an exception we cannot represent exactly is honoured broadly.
export function parseAbpDocumentList(source) {
  if (typeof source !== "string") return [];
  const domains = [];
  const exceptions = new Set();
  const hostname = (value) => value.toLowerCase().replace(/^\.+|\.+$/g, "");
  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.trim();
    const exception = line.match(ABP_EXCEPTION_LINE);
    const block = exception ? null : line.match(ABP_BLOCK_LINE);
    if (!exception && !block) continue;
    const host = hostname((exception || block)[1]);
    if (!isPublicHostname(host)) continue;
    const options = !block || block[2] === undefined ? [] : block[2].split(",");
    if (exception) exceptions.add(host);
    else if (options.every((option) => ABP_DOCUMENT_OPTIONS.has(option) || option.startsWith("reason="))) domains.push(host);
  }
  const released = (domain) => domain.split(".").some((_, index, labels) => exceptions.has(labels.slice(index).join(".")));
  return [...new Set(domains)].filter((domain) => !released(domain)).sort();
}

export function compileDomainRules(domains, options = {}) {
  const {
    startId = 1,
    priority = 100,
    chunkSize = 32,
    maxRuleBytes = 2_048,
    thirdPartyOnly = false,
    resourceTypes = NETWORK_RESOURCE_TYPES
  } = options;
  const normalized = [...new Set(domains.filter(isPublicHostname))].sort();
  const rules = [];

  function createRule(requestDomains) {
    const condition = { requestDomains, resourceTypes: [...resourceTypes] };
    if (thirdPartyOnly) condition.domainType = "thirdParty";
    return {
      id: startId + rules.length,
      priority,
      action: { type: "block" },
      condition
    };
  }

  let offset = 0;
  while (offset < normalized.length) {
    // Without a byte cap (packaged static rules), chunks are simply sliced.
    const requestDomains = maxRuleBytes === Infinity ? normalized.slice(offset, offset + chunkSize) : [];
    while (maxRuleBytes !== Infinity && offset + requestDomains.length < normalized.length && requestDomains.length < chunkSize) {
      const candidate = normalized[offset + requestDomains.length];
      const candidateRule = createRule([...requestDomains, candidate]);
      if (new TextEncoder().encode(JSON.stringify(candidateRule)).byteLength >= maxRuleBytes) {
        if (requestDomains.length === 0) {
          throw new Error(`Domain ${candidate} cannot fit in compiled DNR rule ${candidateRule.id}.`);
        }
        break;
      }
      requestDomains.push(candidate);
    }
    const rule = createRule(requestDomains);
    rules.push(rule);
    offset += requestDomains.length;
  }
  return rules;
}
