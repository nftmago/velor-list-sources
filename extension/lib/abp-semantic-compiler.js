import { getDomain } from "./vendor/tldts.js";
import { isNetworkException, isProtectedPlayerHost } from "./abp-compiler.js";
import { isPublicHostname, NETWORK_RESOURCE_TYPES } from "./domain-rules.js";

const ANCHORED_PATTERN = /^(?<exception>@@)?(?<pattern>\|\|(?<hostname>[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?<tail>[^\s$]*))(?:\$(?<options>[^\s]+))?$/i;
const ANCHORED_HOST = /^(?:@@)?\|\|(?<hostname>[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)/i;
const TYPE_OPTIONS = Object.freeze({
  script: "script",
  image: "image",
  stylesheet: "stylesheet",
  object: "object",
  subdocument: "sub_frame",
  frame: "sub_frame",
  css: "stylesheet",
  xmlhttprequest: "xmlhttprequest",
  xhr: "xmlhttprequest",
  font: "font",
  media: "media",
  ping: "ping",
  websocket: "websocket",
  other: "other"
});
const CONTROL_OPTIONS = new Set(["important", "third-party", "~third-party", "match-case", "badfilter"]);
const SAFE_PATTERN = /^[\x21-\x7e]+$/;
const MAX_FILTER_LENGTH = 1_000;
const MAX_RULE_BYTES = 2_048;
const MAX_INITIATOR_DOMAINS_PER_RULE = 24;
const encoder = new TextEncoder();
const GENERIC_PATTERN = /^(?<exception>@@)?(?<pattern>[^\s$]+)(?:\$(?<options>[^\s]+))?$/;
const MIN_GENERIC_LITERAL = 4;
// Generic patterns never touch YouTube's own player and ad-telemetry hosts.
const PLAYER_REQUEST_DOMAINS = Object.freeze(["googlevideo.com", "youtu.be", "youtube-nocookie.com", "youtube.com", "youtubekids.com", "ytimg.com"]);

function optionsFrom(value) {
  return value ? value.split(",").map((option) => option.trim().toLowerCase()).filter(Boolean) : [];
}

function normalizedDomainOption(value) {
  const included = [];
  const excluded = [];
  for (const rawDomain of value.split("|").filter(Boolean)) {
    const negative = rawDomain.startsWith("~");
    const domain = (negative ? rawDomain.slice(1) : rawDomain).toLowerCase();
    if (!isPublicHostname(domain)) return null;
    (negative ? excluded : included).push(domain);
  }
  return {
    included: [...new Set(included)].sort(),
    excluded: [...new Set(excluded)].sort()
  };
}

function domainRelated(left, right) {
  return left === right || left.endsWith(`.${right}`) || right.endsWith(`.${left}`);
}

function scopesCanOverlap(left, right) {
  if (left.included.length === 0 || right.included.length === 0) return true;
  return left.included.some((leftDomain) => right.included.some((rightDomain) => domainRelated(leftDomain, rightDomain)));
}

function typeSetsCanOverlap(left, right) {
  return left.resourceTypes.some((type) => right.resourceTypes.includes(type));
}

function pathPattern(pattern) {
  return pattern.replace(/^\|\|[a-z0-9.-]+/i, "");
}

function literalPrefix(pattern) {
  const path = pathPattern(pattern);
  const wildcard = path.search(/[\^*|]/);
  return wildcard < 0 ? path : path.slice(0, wildcard);
}

function patternsCanOverlap(left, right) {
  if (left === right) return true;
  const leftPath = pathPattern(left);
  const rightPath = pathPattern(right);
  if (!leftPath || leftPath === "^" || !rightPath || rightPath === "^") return true;
  const leftPrefix = literalPrefix(left);
  const rightPrefix = literalPrefix(right);
  return leftPrefix.startsWith(rightPrefix) || rightPrefix.startsWith(leftPrefix);
}

function normalizedFilterKey(parsed) {
  const options = [...parsed.rawOptions].filter((option) => option !== "badfilter").sort();
  return `${parsed.exception ? "@@" : ""}${parsed.pattern}${options.length ? `$${options.join(",")}` : ""}`;
}

// Unanchored URL patterns (/ads/banner., &ad_type=) are accepted only when
// they keep a literal run long enough to be specific; regex filters, mid-pattern
// anchors and cosmetic syntax are refused.
function genericPatternMatch(line) {
  const match = line.match(GENERIC_PATTERN);
  if (!match?.groups) return null;
  const { pattern } = match.groups;
  if (pattern.startsWith("||") || /#[@?$%]?#|#\+js/.test(line)) return null;
  if (pattern.length > 2 && pattern.startsWith("/") && pattern.endsWith("/")) return null;
  if (/\|\|/.test(pattern) || /.\|./.test(pattern)) return null;
  if (Math.max(0, ...pattern.split(/[*^|]/).map((run) => run.length)) < MIN_GENERIC_LITERAL) return null;
  return match;
}

export function parseConservativeAbpNetworkLine(rawLine, { generic = false } = {}) {
  const line = String(rawLine || "").trim();
  if (!line || line.startsWith("!") || line.startsWith("[") || line.startsWith("#")) return null;
  const match = line.match(ANCHORED_PATTERN) || (generic ? genericPatternMatch(line) : null);
  if (!match?.groups) return null;
  const hostname = match.groups.hostname?.toLowerCase() || "";
  const pattern = match.groups.pattern;
  const tail = match.groups.tail || "";
  if ((hostname && !isPublicHostname(hostname)) || pattern.length > MAX_FILTER_LENGTH || !SAFE_PATTERN.test(pattern)) return null;
  if (hostname && tail && !tail.startsWith("^") && !tail.startsWith("/") && !tail.startsWith("?")) return null;
  const rawOptions = optionsFrom(match.groups.options);
  const positiveTypes = [];
  const negativeTypes = [];
  let domainScope = { included: [], excluded: [] };
  let domainType = null;
  let important = false;
  let matchCase = false;
  let badfilter = false;
  let redirect = null;
  const unsupportedOptions = [];
  for (const option of rawOptions) {
    const negative = option.startsWith("~");
    const base = negative ? option.slice(1) : option;
    if (TYPE_OPTIONS[base]) {
      (negative ? negativeTypes : positiveTypes).push(TYPE_OPTIONS[base]);
    } else if (option.startsWith("domain=")) {
      const parsedDomains = normalizedDomainOption(option.slice("domain=".length));
      if (!parsedDomains) unsupportedOptions.push(option);
      else domainScope = parsedDomains;
    } else if (["third-party", "3p", "~first-party", "~1p"].includes(option)) {
      domainType = "thirdParty";
    } else if (["~third-party", "~3p", "first-party", "1p"].includes(option)) {
      domainType = "firstParty";
    } else if (option.startsWith("redirect=") || option.startsWith("redirect-rule=")) {
      const [name, value] = option.split("=");
      redirect = { name: value, onlyIfBlocked: name === "redirect-rule" };
    } else if (option === "important") {
      important = true;
    } else if (option === "match-case") {
      matchCase = true;
    } else if (option === "badfilter") {
      badfilter = true;
    } else if (!CONTROL_OPTIONS.has(option)) {
      unsupportedOptions.push(option);
    }
  }
  const defaultTypes = [...NETWORK_RESOURCE_TYPES];
  const resourceTypes = [...new Set(positiveTypes.length > 0 ? positiveTypes : defaultTypes)]
    .filter((type) => !negativeTypes.includes(type));
  if (resourceTypes.length === 0) unsupportedOptions.push("empty-resource-set");
  const domainOnly = Boolean(hostname) && (tail === "" || tail === "^");
  const hasSemanticConstraint = (
    positiveTypes.length > 0
    || negativeTypes.length > 0
    || domainScope.included.length > 0
    || domainScope.excluded.length > 0
    || domainType === "firstParty"
    || matchCase
    || redirect !== null
  );
  return {
    line,
    exception: Boolean(match.groups.exception),
    hostname,
    pattern,
    tail,
    domainOnly,
    generic: !hostname,
    hasSemanticConstraint,
    rawOptions,
    resourceTypes,
    domainScope,
    domainType,
    important,
    matchCase,
    badfilter,
    redirect,
    unsupportedOptions,
    key: ""
  };
}

function hostnameFromUnparsedException(line) {
  return line.match(ANCHORED_HOST)?.groups?.hostname?.toLowerCase() || "";
}

function exceptionIndexFor(sources) {
  const byHostname = new Map();
  for (const source of sources) {
    for (const rawLine of String(source || "").split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line.startsWith("@@||") || !isNetworkException(line)) continue;
      const parsed = parseConservativeAbpNetworkLine(line);
      const hostname = parsed?.hostname || hostnameFromUnparsedException(line);
      if (!isPublicHostname(hostname)) continue;
      const values = byHostname.get(hostname) || [];
      values.push(parsed || { line, hostname, pattern: line.split("$", 1)[0].slice(2), unsupported: true });
      byHostname.set(hostname, values);
    }
  }
  return byHostname;
}

function badfilterIndexFor(sources) {
  const disabled = new Set();
  for (const source of sources) {
    for (const rawLine of String(source || "").split(/\r?\n/)) {
      const parsed = parseConservativeAbpNetworkLine(rawLine, { generic: true });
      if (!parsed?.badfilter) continue;
      parsed.key = normalizedFilterKey(parsed);
      disabled.add(parsed.key);
    }
  }
  return disabled;
}

function matchingExceptions(candidate, byHostname) {
  const related = [];
  for (const [hostname, exceptions] of byHostname) {
    if (!domainRelated(candidate.hostname, hostname)) continue;
    for (const exception of exceptions) {
      if (!patternsCanOverlap(candidate.pattern, exception.pattern)) continue;
      if (!exception.unsupported) {
        if (!typeSetsCanOverlap(candidate, exception)) continue;
        if (!scopesCanOverlap(candidate.domainScope, exception.domainScope)) continue;
      }
      related.push(exception);
    }
  }
  return related;
}

function foldExceptions(candidate, exceptions) {
  const excludedInitiators = new Set(candidate.domainScope.excluded);
  for (const exception of exceptions) {
    if (exception.unsupported || exception.domainType || exception.domainScope.included.length === 0) {
      return null;
    }
    for (const domain of exception.domainScope.included) excludedInitiators.add(domain);
  }
  return [...excludedInitiators].sort();
}

function chunked(values, size) {
  if (values.length === 0) return [[]];
  const chunks = [];
  for (let offset = 0; offset < values.length; offset += size) chunks.push(values.slice(offset, offset + size));
  return chunks;
}

function buildConditions(candidate, excludedInitiatorDomains) {
  const base = {
    resourceTypes: candidate.resourceTypes
  };
  if (candidate.domainOnly) base.requestDomains = [candidate.hostname];
  else base.urlFilter = candidate.pattern;
  if (candidate.matchCase) base.isUrlFilterCaseSensitive = true;
  if (candidate.domainType) base.domainType = candidate.domainType;
  if (excludedInitiatorDomains.length > 0) base.excludedInitiatorDomains = excludedInitiatorDomains;
  if (candidate.generic && !candidate.exception) base.excludedRequestDomains = [...PLAYER_REQUEST_DOMAINS];
  return chunked(candidate.domainScope.included, MAX_INITIATOR_DOMAINS_PER_RULE).map((initiatorDomains) => ({
    ...base,
    ...(initiatorDomains.length > 0 ? { initiatorDomains } : {})
  }));
}

export function compileConservativeAbpSemanticRules(source, options = {}) {
  const startId = Number.isSafeInteger(options.startId) ? options.startId : 1;
  const priority = Number.isSafeInteger(options.priority) ? options.priority : 130;
  const exceptionSources = Array.isArray(options.exceptionSources) ? options.exceptionSources : [source];
  const sharedInfrastructureRoots = options.sharedInfrastructureRoots || new Set();
  const excludedFingerprints = options.excludedFingerprints || new Set();
  const generic = options.generic === true;
  // Redirect filters serve a packaged stand-in instead of blocking. Without a
  // resolver, or for an unknown stand-in, they are rejected.
  const redirectPathFor = options.redirectPathFor || (() => null);
  const blockedHostsUnder = options.blockedHostsUnder || (() => []);
  // `@@…$redirect-rule` exceptions: scoped ones exclude their sites from the
  // stand-in, an unscoped one turns it back into a plain block.
  const redirectExceptions = (options.redirectExceptions || [])
    .map((line) => withoutEntityDomains(line))
    .map((line) => line && parseConservativeAbpNetworkLine(line, { generic: true }))
    .filter((parsed) => parsed?.hostname);
  const exceptions = exceptionIndexFor(exceptionSources);
  const badfilters = badfilterIndexFor(Array.isArray(options.badfilterSources) ? options.badfilterSources : exceptionSources);
  const rules = [];
  const fingerprints = new Set();
  const rejected = {
    unsupportedShape: 0,
    unsupportedOptions: 0,
    exactDomainHandledElsewhere: 0,
    badfilter: 0,
    exceptionConflict: 0,
    sharedInfrastructure: 0,
    protectedPlayerEndpoint: 0,
    duplicate: 0,
    oversized: 0
  };
  let acceptedFilters = 0;

  for (const rawLine of String(source || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("!") || line.startsWith("[") || line.startsWith("#") || line.startsWith("@@")) continue;
    const candidate = parseConservativeAbpNetworkLine(line, { generic });
    if (!candidate) {
      rejected.unsupportedShape += 1;
      continue;
    }
    candidate.key = normalizedFilterKey(candidate);
    if (candidate.badfilter || badfilters.has(candidate.key)) {
      rejected.badfilter += 1;
      continue;
    }
    if (candidate.unsupportedOptions.length > 0) {
      rejected.unsupportedOptions += 1;
      continue;
    }
    if (candidate.domainOnly && !candidate.hasSemanticConstraint) {
      rejected.exactDomainHandledElsewhere += 1;
      continue;
    }
    if (sharedInfrastructureRoots.has(candidate.hostname) && candidate.domainOnly) {
      rejected.sharedInfrastructure += 1;
      continue;
    }
    if (candidate.hostname && isProtectedPlayerHost(candidate.hostname)) {
      rejected.protectedPlayerEndpoint += 1;
      continue;
    }
    const matching = matchingExceptions(candidate, exceptions);
    let excludedInitiators = foldExceptions(candidate, matching);
    if (excludedInitiators === null) {
      rejected.exceptionConflict += 1;
      continue;
    }
    let action = { type: "block" };
    let requestDomains = null;
    if (candidate.redirect) {
      const extensionPath = redirectPathFor(candidate.redirect.name);
      // redirect-rule only replaces requests something else already blocks:
      // the whole host, or just its blocked subdomains. A stand-in excepted
      // anywhere for this host falls back to a block.
      const blocked = candidate.redirect.onlyIfBlocked && candidate.hostname ? blockedHostsUnder(candidate.hostname) : null;
      if (!extensionPath || !candidate.hostname || blocked?.length === 0) {
        rejected.unsupportedOptions += 1;
        continue;
      }
      if (blocked && !(blocked.length === 1 && blocked[0] === candidate.hostname)) requestDomains = blocked;
      const excepted = redirectExceptions.filter((exception) => (
        domainRelated(candidate.hostname, exception.hostname) && patternsCanOverlap(candidate.pattern, exception.pattern)
      ));
      if (excepted.some((exception) => exception.domainScope.included.length === 0)) {
        if (candidate.redirect.onlyIfBlocked) {
          rejected.exceptionConflict += 1;
          continue;
        }
      } else {
        action = { type: "redirect", redirect: { extensionPath } };
        excludedInitiators = [...new Set([...excludedInitiators, ...excepted.flatMap((exception) => exception.domainScope.included)])].sort();
      }
    }
    const conditions = buildConditions(candidate, excludedInitiators)
      .map((condition) => (requestDomains ? { ...condition, requestDomains } : condition));
    const candidateRules = conditions.map((condition) => ({
      id: startId + rules.length,
      // A stand-in must outrank the plain block it replaces.
      priority: priority + (candidate.important ? 100 : 0) + (action.type === "redirect" ? 20 : 0),
      action,
      condition
    }));
    if (candidateRules.some((rule) => encoder.encode(JSON.stringify(rule)).byteLength >= MAX_RULE_BYTES)) {
      rejected.oversized += 1;
      continue;
    }
    const candidateFingerprints = candidateRules.map((rule) => JSON.stringify({
      priority: rule.priority,
      action: rule.action,
      condition: rule.condition
    }));
    if (candidateFingerprints.some((fingerprint) => fingerprints.has(fingerprint) || excludedFingerprints.has(fingerprint))) {
      rejected.duplicate += 1;
      continue;
    }
    acceptedFilters += 1;
    for (let index = 0; index < candidateRules.length; index += 1) {
      const rule = { ...candidateRules[index], id: startId + rules.length };
      const fingerprint = JSON.stringify({ priority: rule.priority, action: rule.action, condition: rule.condition });
      fingerprints.add(fingerprint);
      rules.push(rule);
    }
  }

  return { rules, fingerprints, acceptedFilters, rejected };
}

const DOCUMENT_EXCEPTION_OPTIONS = new Set(["document", "doc", "urlblock"]);

function withoutEntityDomains(line) {
  const separator = line.indexOf("$");
  if (separator < 0) return line;
  const options = line.slice(separator + 1).split(",").map((option) => {
    if (!option.startsWith("domain=")) return option;
    const domains = option.slice("domain=".length).split("|").filter((domain) => !domain.endsWith(".*"));
    return domains.length > 0 ? `domain=${domains.join("|")}` : null;
  });
  return options.includes(null) ? null : `${line.slice(0, separator)}$${options.join(",")}`;
}

// List exceptions become packaged allow rules. Their priority sits above
// ordinary list blocks and below $important blocks, cryptomining, threats and
// every user choice, which mirrors how filter lists resolve exceptions.
// Exceptions that cannot be expressed exactly are returned as hostnames so
// callers can fall back to dropping the related blocks.
export function compileAbpExceptionRules(sources, options = {}) {
  const startId = Number.isSafeInteger(options.startId) ? options.startId : 1;
  const priority = Number.isSafeInteger(options.priority) ? options.priority : 190;
  const badfilters = badfilterIndexFor(sources);
  const rules = [];
  const fingerprints = new Set();
  const unconvertible = [];
  const rejected = { nonNetwork: 0, entityOnly: 0, unanchored: 0, badfilter: 0, unsupportedOptions: 0, publicSuffix: 0, duplicate: 0, oversized: 0 };
  for (const source of sources) {
    for (const rawLine of String(source || "").split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line.startsWith("@@")) continue;
      if (!isNetworkException(line)) {
        rejected.nonNetwork += 1;
        continue;
      }
      // Chrome cannot express wildcard-TLD sites (example.*): the exception
      // keeps its other sites, and one that names only such sites is skipped.
      const scoped = withoutEntityDomains(line);
      if (!scoped) {
        rejected.entityOnly += 1;
        continue;
      }
      const parsed = parseConservativeAbpNetworkLine(scoped, { generic: options.generic === true });
      if (!parsed) {
        rejected.unanchored += 1;
        continue;
      }
      parsed.key = normalizedFilterKey(parseConservativeAbpNetworkLine(line, { generic: options.generic === true }) || parsed);
      if (parsed.badfilter || badfilters.has(parsed.key)) {
        rejected.badfilter += 1;
        continue;
      }
      const documentLike = parsed.unsupportedOptions.some((option) => DOCUMENT_EXCEPTION_OPTIONS.has(option));
      const unsupported = parsed.unsupportedOptions.filter((option) => !DOCUMENT_EXCEPTION_OPTIONS.has(option));
      if (unsupported.length > 0 || (documentLike && parsed.domainScope.included.length > 0)) {
        rejected.unsupportedOptions += 1;
        unconvertible.push(line);
        continue;
      }
      if (parsed.hostname && getDomain(parsed.hostname) === null) {
        rejected.publicSuffix += 1;
        continue;
      }
      const conditions = documentLike
        ? [{ ...(parsed.domainOnly ? { requestDomains: [parsed.hostname] } : { urlFilter: parsed.pattern }), resourceTypes: ["main_frame", "sub_frame"] }]
        : buildConditions(parsed, parsed.domainScope.excluded);
      const candidateRules = conditions.map((condition) => ({
        id: 0,
        priority,
        action: { type: documentLike ? "allowAllRequests" : "allow" },
        condition
      }));
      if (candidateRules.some((rule) => encoder.encode(JSON.stringify(rule)).byteLength >= MAX_RULE_BYTES)) {
        rejected.oversized += 1;
        unconvertible.push(line);
        continue;
      }
      const keys = candidateRules.map((rule) => JSON.stringify({ action: rule.action, condition: rule.condition }));
      if (keys.every((key) => fingerprints.has(key))) {
        rejected.duplicate += 1;
        continue;
      }
      for (const [index, rule] of candidateRules.entries()) {
        if (fingerprints.has(keys[index])) continue;
        fingerprints.add(keys[index]);
        rules.push({ ...rule, id: startId + rules.length });
      }
    }
  }
  return { rules, unconvertible, rejected };
}
