import {
  applyListConditions,
  createExceptionIndex,
  extractConservativeAbpDomains,
  extractPopupHosts,
  hasExceptionConflict,
  SHARED_INFRASTRUCTURE_ROOTS
} from "./abp-compiler.js";
import { compileAbpExceptionRules, compileConservativeAbpSemanticRules } from "./abp-semantic-compiler.js";
import { compileDomainRules, NETWORK_RESOURCE_TYPES } from "./domain-rules.js";
import { redirectPathFor } from "./redirect-resources.js";

// Compiles the ad and tracker lists into Velor's network rulesets. Runs in the
// build (scripts/compile-rules.mjs) and in the service worker alike, so it
// takes list texts and returns plain data.
//
// `lists`: PRIVACY_SOURCES entries in order, each with its `text`.
// `starterDomains`: hostnames the packaged network_privacy ruleset already
// blocks; they are left out of the expanded rules.
//
// Returns:
//   expandedRules   expanded_privacy: packed `||host^` blocks per list
//   semanticRules   semantic_privacy: path, pattern and stand-in rules
//   exceptionRules  privacy_exceptions: allow rules from list exceptions
//   popupHosts      sorted `$popup`/`$document` hosts for the pop-up defense
//   exceptions      { unconvertible, rejected, excludedDomains }: exception
//                   filters that became no rule, the exception compiler's
//                   rejection counts, and the hostnames those filters and
//                   badfilters removed from every list
//   sources         one entry per list, in order: { id, domains,
//                   importantDomains, semanticRules, acceptedFilters,
//                   rejected } with the hostnames and semantic rules the
//                   list contributed (arrays; `importantDomains` is the
//                   `$important` subset of `domains`), the semantic
//                   filters accepted and the semantic rejection counts
export function compilePrivacyLists(lists, { starterDomains }) {
  const sources = lists.map((source) => {
    const text = applyListConditions(source.text);
    return { ...source, text, parsed: extractConservativeAbpDomains(text, { applyExceptions: false }) };
  });
  const listTexts = sources.map((source) => source.text);

  // Every list's exceptions become allow rules in privacy_exceptions, so a host
  // with a site-specific exception stays blocked everywhere else. Only
  // exceptions that cannot be expressed exactly, and badfilters, still remove
  // the related hostname blocks from every list.
  const exceptionRules = compileAbpExceptionRules(listTexts, { startId: 1, priority: 190, generic: true });
  const unconvertibleExceptions = exceptionRules.unconvertible.join("\n");
  const globalAbpExclusions = new Set([
    ...extractConservativeAbpDomains(unconvertibleExceptions).exceptions,
    ...sources.flatMap((source) => source.parsed.badfilters)
  ]);
  const globalAbpExceptionIndex = createExceptionIndex(globalAbpExclusions);
  const domainOwners = new Map();
  for (const source of sources) {
    const important = new Set(source.parsed.important);
    for (const domain of source.parsed.domains) {
      if (domainOwners.has(domain) || starterDomains.has(domain) || hasExceptionConflict(domain, globalAbpExceptionIndex)) continue;
      domainOwners.set(domain, { id: source.id, important: important.has(domain) });
    }
  }
  // Expanded rules share one third-party subresource condition, so a listed
  // parent covers its subdomains unless the child is $important and the parent
  // is not.
  const coveredByParent = (domain, important) => domain.split(".").some((_, index, labels) => {
    const parent = index > 0 && index < labels.length - 1 && domainOwners.get(labels.slice(index).join("."));
    return parent && (parent.important || !important);
  });
  const domainsBySource = new Map(sources.map((source) => [source.id, { normal: [], important: [] }]));
  for (const [domain, { id, important }] of domainOwners) {
    if (!coveredByParent(domain, important)) domainsBySource.get(id)[important ? "important" : "normal"].push(domain);
  }

  // Chrome has no per-rule size limit for packaged rules (uBlock Origin Lite
  // ships single rules with 40,000+ domains), so each list packs its hostnames
  // into a few large rules instead of spending the 30,000-rule budget.
  const expandedRules = sources.flatMap((source) => {
    const options = { chunkSize: 25_000, maxRuleBytes: Infinity, thirdPartyOnly: true, resourceTypes: NETWORK_RESOURCE_TYPES };
    const { normal, important } = domainsBySource.get(source.id);
    const normalRules = compileDomainRules(normal, { ...options, startId: source.startId, priority: source.kind === "trackers" ? 120 : 110 });
    // $important hosts outrank list exceptions, as they do in filter lists.
    return [...normalRules, ...compileDomainRules(important, { ...options, startId: source.startId + normalRules.length, priority: 230 })];
  });

  // redirect-rule filters apply only where a list already blocks the host.
  const blockedHosts = new Set([...domainOwners.keys(), ...starterDomains]);
  const blockedHostsUnder = (hostname) => {
    const labels = hostname.split(".");
    if (labels.some((_, index) => index < labels.length - 1 && blockedHosts.has(labels.slice(index).join(".")))) return [hostname];
    return [...blockedHosts].filter((host) => host.endsWith(`.${hostname}`)).sort();
  };
  // Exceptions aimed at a stand-in (`@@||host^$redirect-rule,domain=…`).
  const redirectExceptions = listTexts.flatMap((text) => text.split(/\r?\n/))
    .map((line) => line.trim())
    .filter((line) => /^@@\|\|[^$\s]*\$(?:[^\s]*,)?redirect(?:-rule)?(?:[=,]|$)/i.test(line));
  const semanticFingerprints = new Set();
  const semanticBySource = sources.map((source) => {
    const compiled = compileConservativeAbpSemanticRules(source.text, {
      startId: source.startId,
      priority: 130,
      exceptionSources: [unconvertibleExceptions],
      badfilterSources: listTexts,
      generic: true,
      redirectPathFor,
      blockedHostsUnder,
      redirectExceptions,
      sharedInfrastructureRoots: SHARED_INFRASTRUCTURE_ROOTS,
      excludedFingerprints: semanticFingerprints
    });
    for (const fingerprint of compiled.fingerprints) semanticFingerprints.add(fingerprint);
    return compiled;
  });

  return {
    expandedRules,
    semanticRules: semanticBySource.flatMap((compiled) => compiled.rules),
    exceptionRules: exceptionRules.rules,
    popupHosts: extractPopupHosts(listTexts),
    exceptions: {
      unconvertible: exceptionRules.unconvertible,
      rejected: exceptionRules.rejected,
      excludedDomains: [...globalAbpExclusions]
    },
    sources: sources.map((source, index) => {
      const { normal, important } = domainsBySource.get(source.id);
      return {
        id: source.id,
        domains: [...normal, ...important],
        importantDomains: important,
        semanticRules: semanticBySource[index].rules,
        acceptedFilters: semanticBySource[index].acceptedFilters,
        rejected: semanticBySource[index].rejected
      };
    })
  };
}
