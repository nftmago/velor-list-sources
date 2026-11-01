import { isPublicHostname } from "./rule-compiler.mjs";
import { applyListConditions } from "../extension/lib/abp-compiler.js";
import {
  COSMETIC_BUCKET_COUNT,
  cosmeticBucketFor,
  cosmeticBucketName
} from "../extension/lib/cosmetic-index.js";

export const MAX_COSMETIC_SELECTOR_LENGTH = 512;
export const MAX_GLOBAL_COSMETIC_SELECTORS = 6_000;
export const MAX_DOMAIN_COSMETIC_SELECTORS = 64_000;
export const MAX_COSMETIC_SELECTORS_PER_DOMAIN = 256;

const UNSAFE_SELECTOR = /[{};@\\\u0000-\u001f\u007f]|\/\*|\*\//;
const EXTENDED_SELECTOR = /(?:^\^|\+js\s*\(|:-abp-|:(?:has|has-text|matches-css(?:-before|-after)?|xpath|upward|remove|style|watch-attr|others)\s*\()/i;
const SIMPLE_ID = /^#[a-z_][a-z0-9_-]{2,127}$/i;
const SIMPLE_CLASS = /^\.[a-z_][a-z0-9_-]{2,127}$/i;
const SIMPLE_COMPOUND = /^(?:[a-z][a-z0-9-]*)?(?:#[a-z_][a-z0-9_-]{2,127}|\.[a-z_][a-z0-9_-]{2,127})(?:(?:#[a-z_][a-z0-9_-]{2,127}|\.[a-z_][a-z0-9_-]{2,127}))*$/i;
const ATTRIBUTE_AD_MARKER = /\[(?:id|class)(?:[*^$~|]?=)["']?[^\]]*(?:^|[-_ ])(?:ads?|advert(?:isement|ising)?|sponsor(?:ed)?|promoted?)(?:[-_ 0-9]|$)/i;

function balancedSelector(selector) {
  const pairs = { ")": "(", "]": "[" };
  const stack = [];
  let quote = "";
  for (let index = 0; index < selector.length; index += 1) {
    const character = selector[index];
    if (quote) {
      if (character === quote) quote = "";
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
    } else if (character === "(" || character === "[") {
      stack.push(character);
    } else if (pairs[character]) {
      if (stack.pop() !== pairs[character]) return false;
    }
  }
  return quote === "" && stack.length === 0;
}

export function isSafeCosmeticSelector(selector) {
  const value = String(selector || "").trim();
  return Boolean(
    value
    && value.length <= MAX_COSMETIC_SELECTOR_LENGTH
    && !UNSAFE_SELECTOR.test(value)
    && !EXTENDED_SELECTOR.test(value)
    && balancedSelector(value)
  );
}

function genericSelectorRank(selector) {
  if (SIMPLE_ID.test(selector)) return 0;
  if (SIMPLE_CLASS.test(selector)) return 1;
  if (SIMPLE_COMPOUND.test(selector)) return 2;
  if (ATTRIBUTE_AD_MARKER.test(selector)) return 3;
  return Number.POSITIVE_INFINITY;
}

function parseScope(rawScope) {
  if (!rawScope) return { included: [], excluded: [] };
  const included = [];
  const excluded = [];
  for (const rawValue of rawScope.split(",")) {
    const trimmed = rawValue.trim().toLowerCase();
    if (!trimmed) return null;
    const negative = trimmed.startsWith("~");
    const domain = negative ? trimmed.slice(1) : trimmed;
    if (!isPublicHostname(domain) || domain.includes("*")) return null;
    (negative ? excluded : included).push(domain);
  }
  return {
    included: [...new Set(included)].sort(),
    excluded: [...new Set(excluded)].sort()
  };
}

export function parseConservativeCosmeticLine(rawLine) {
  const line = String(rawLine || "").trim();
  if (!line || line.startsWith("!") || line.startsWith("[")) return null;
  const exceptionAt = line.indexOf("#@#");
  const hideAt = line.indexOf("##");
  const exception = exceptionAt >= 0;
  const delimiterAt = exception ? exceptionAt : hideAt;
  const delimiterLength = exception ? 3 : 2;
  if (delimiterAt < 0) return null;
  const rawScope = line.slice(0, delimiterAt);
  const selector = line.slice(delimiterAt + delimiterLength).trim();
  const scope = parseScope(rawScope);
  if (!scope) return { line, rejected: "invalidScope" };
  if (scope.excluded.length > 0 && scope.included.length === 0) {
    return { line, rejected: "negativeOnlyScope" };
  }
  if (!isSafeCosmeticSelector(selector)) return { line, rejected: "unsafeOrExtendedSelector" };
  if (!exception && scope.included.length === 0 && !Number.isFinite(genericSelectorRank(selector))) {
    return { line, rejected: "lowConfidenceGeneric" };
  }
  return {
    line,
    exception,
    selector,
    scope,
    global: scope.included.length === 0,
    rank: genericSelectorRank(selector)
  };
}

function createRejectedCounts() {
  return {
    unsupportedSyntax: 0,
    invalidScope: 0,
    negativeOnlyScope: 0,
    unsafeOrExtendedSelector: 0,
    lowConfidenceGeneric: 0,
    duplicate: 0,
    exceptionSuppressedGeneric: 0,
    globalBudget: 0,
    domainBudget: 0,
    perDomainBudget: 0
  };
}

function ensureDomainEntry(domainEntries, domain) {
  if (!domainEntries.has(domain)) domainEntries.set(domain, { hide: new Map(), exceptions: new Set() });
  return domainEntries.get(domain);
}

export function compileConservativeCosmeticRules(sources, options = {}) {
  const sourceList = (Array.isArray(sources) ? sources : [sources]).map(applyListConditions);
  const maximumGlobal = options.maximumGlobal ?? MAX_GLOBAL_COSMETIC_SELECTORS;
  const maximumDomain = options.maximumDomain ?? MAX_DOMAIN_COSMETIC_SELECTORS;
  const maximumPerDomain = options.maximumPerDomain ?? MAX_COSMETIC_SELECTORS_PER_DOMAIN;
  const rejected = createRejectedCounts();
  const globalCandidates = new Map();
  const allScopedExceptions = new Set();
  const globalExceptions = new Set();
  const domainEntries = new Map();
  let parsedFilters = 0;

  for (const source of sourceList) {
    for (const rawLine of String(source || "").split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("!") || line.startsWith("[")) continue;
      const parsed = parseConservativeCosmeticLine(line);
      if (!parsed) {
        if (line.includes("#")) rejected.unsupportedSyntax += 1;
        continue;
      }
      if (parsed.rejected) {
        rejected[parsed.rejected] += 1;
        continue;
      }
      parsedFilters += 1;
      if (parsed.exception) {
        if (parsed.global) globalExceptions.add(parsed.selector);
        else {
          allScopedExceptions.add(parsed.selector);
          for (const domain of parsed.scope.included) {
            ensureDomainEntry(domainEntries, domain).exceptions.add(parsed.selector);
          }
        }
        continue;
      }
      if (parsed.global) {
        if (globalCandidates.has(parsed.selector)) rejected.duplicate += 1;
        else globalCandidates.set(parsed.selector, parsed.rank);
        continue;
      }
      for (const domain of parsed.scope.included) {
        const entry = ensureDomainEntry(domainEntries, domain);
        const fingerprint = `${parsed.selector}\u0000${parsed.scope.excluded.join("|")}`;
        if (entry.hide.has(fingerprint)) rejected.duplicate += 1;
        else entry.hide.set(fingerprint, [parsed.selector, parsed.scope.excluded]);
      }
    }
  }

  for (const selector of new Set([...globalExceptions, ...allScopedExceptions])) {
    if (globalCandidates.delete(selector)) rejected.exceptionSuppressedGeneric += 1;
  }
  const rankedGlobals = [...globalCandidates]
    .sort(([leftSelector, leftRank], [rightSelector, rightRank]) => (
      leftRank - rightRank || leftSelector.localeCompare(rightSelector)
    ));
  rejected.globalBudget = Math.max(0, rankedGlobals.length - maximumGlobal);
  const globalSelectors = rankedGlobals.slice(0, maximumGlobal).map(([selector]) => selector);

  let remainingDomainBudget = maximumDomain;
  const buckets = Array.from({ length: COSMETIC_BUCKET_COUNT }, (_, index) => ({
    formatVersion: 1,
    bucket: cosmeticBucketName(index),
    domains: {}
  }));
  let domainSelectors = 0;
  let exceptionSelectors = 0;
  for (const domain of [...domainEntries.keys()].sort()) {
    const sourceEntry = domainEntries.get(domain);
    const hides = [...sourceEntry.hide.values()].sort(([left], [right]) => left.localeCompare(right));
    const acceptedHides = hides.slice(0, Math.min(maximumPerDomain, remainingDomainBudget));
    rejected.perDomainBudget += Math.max(0, hides.length - maximumPerDomain);
    rejected.domainBudget += Math.max(0, Math.min(hides.length, maximumPerDomain) - remainingDomainBudget);
    remainingDomainBudget = Math.max(0, remainingDomainBudget - acceptedHides.length);
    const exceptions = [...sourceEntry.exceptions].sort();
    if (acceptedHides.length === 0 && exceptions.length === 0) continue;
    const entry = { hide: acceptedHides, exceptions };
    buckets[cosmeticBucketFor(domain)].domains[domain] = entry;
    domainSelectors += acceptedHides.length;
    exceptionSelectors += exceptions.length;
  }

  return {
    formatVersion: 1,
    bucketCount: COSMETIC_BUCKET_COUNT,
    parsedFilters,
    globalSelectors,
    domainSelectors,
    exceptionSelectors,
    buckets,
    rejected
  };
}

// Nested rules keep each selector's own id/class as its rightmost compound,
// so Chrome indexes them; wrapped in :is() every element was checked against
// every selector (about 10 ms of style work per page). Generic selectors are
// simple ids, classes and attributes, so one list per chunk is safe. The page
// switch is the content script's attribute: data-velor-list-cosmetic for the
// ad lists (off in Brave companion mode), data-velor-cosmetic for annoyances.
function cssChunk(selectors, attribute) {
  return `html[${attribute}="on"]{${selectors.map((selector) => `& ${selector}`).join(",")}{display:none!important;visibility:hidden!important;pointer-events:none!important}}`;
}

export function renderCompiledCosmeticCss(selectors, { chunkSize = 400, attribute = "data-velor-list-cosmetic" } = {}) {
  const chunks = [];
  for (let index = 0; index < selectors.length; index += chunkSize) {
    chunks.push(cssChunk(selectors.slice(index, index + chunkSize), attribute));
  }
  return `/* Generated from reviewed filter-list snapshots. Do not edit. */\n${chunks.join("\n")}\n`;
}
