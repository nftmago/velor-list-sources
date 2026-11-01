import { THREAT_FEEDS, compileThreatFeeds, parseThreatFeed } from "../extension/lib/threat-policy.js";
import { PRIVACY_SOURCES } from "../extension/lib/privacy-sources.js";
import { ANNOYANCE_GROUPS } from "../extension/lib/annoyance-sources.js";
import { REGIONAL_LISTS } from "../extension/lib/regional-sources.js";
import { OPTIONAL_ALLOW_START, optionalScriptletAllowed } from "../extension/lib/optional-lists.js";
import { cosmeticBucketName } from "../extension/lib/cosmetic-index.js";
import { compilePrivacyLists } from "../extension/lib/privacy-compiler.js";
import { scriptletFor } from "../extension/scriptlets/library.js";
import { compileScriptletTables, renderPageScriptFile } from "./scriptlet-compiler.mjs";
import { siteExcludeMatches } from "../extension/lib/scriptlet-registration.js";
import { compileUrlCleanup } from "./url-cleanup-compiler.mjs";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PROTECTED_PLAYER_ROOTS } from "../extension/lib/abp-compiler.js";
import {
  compileConservativeCosmeticRules,
  MAX_DOMAIN_COSMETIC_SELECTORS,
  renderCompiledCosmeticCss
} from "./cosmetic-compiler.mjs";
import {
  compileDomainRules,
  NETWORK_RESOURCE_TYPES,
  parseDomainList,
  sha256,
  THREAT_RESOURCE_TYPES
} from "./rule-compiler.mjs";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataDirectory = resolve(projectRoot, "filter-data");
const rulesDirectory = resolve(projectRoot, "extension/rules");
const contentDirectory = resolve(projectRoot, "extension/content");

async function read(name) {
  return readFile(resolve(dataDirectory, name), "utf8");
}

// A list snapshot and the sub-lists it includes (`<id>--<name>.txt`), each
// checked against the list's reviewed metadata. `text` is the list itself,
// `fullText` the list with its sub-lists.
async function readList(source) {
  const [text, metadataText] = await Promise.all([read(`${source.id}.txt`), read(`${source.id}-source.json`)]);
  const metadata = JSON.parse(metadataText);
  if (metadata.sha256 !== sha256(text) || metadata.source !== source.url) throw new Error(`${source.id} snapshot does not match its reviewed metadata.`);
  const includes = await Promise.all((metadata.includes || []).map(async (include) => {
    if (include.file !== `${source.id}--${include.name}` || !/^[\w.-]+$/.test(include.name)) throw new Error(`${source.id} names an unexpected sub-list.`);
    const included = await read(include.file);
    if (sha256(included) !== include.sha256) throw new Error(`${include.file} does not match its reviewed metadata.`);
    return included;
  }));
  return { text, fullText: [text, ...includes].join("\n"), metadata };
}

async function writeJson(name, value) {
  await writeFile(resolve(rulesDirectory, name), `${JSON.stringify(value, null, 2)}\n`);
}

// Each optional family (annoyance groups, regional lists) shares one set of
// site buckets, each list in its own section, so the worker reads one more
// file per site only while a list of that family is on. Generic selectors go
// to one stylesheet per list behind the family's page switch.
async function writeOptionalCosmeticArtifacts({ family, groups }) {
  const cosmeticDirectory = resolve(rulesDirectory, "cosmetic");
  const bucketsDirectory = resolve(cosmeticDirectory, family.id);
  await rm(bucketsDirectory, { recursive: true, force: true });
  await mkdir(bucketsDirectory, { recursive: true });
  await Promise.all([
    ...groups.map(({ group, cosmetic }) => writeFile(
      resolve(cosmeticDirectory, `${family.id}-${group.id}.css`),
      renderCompiledCosmeticCss(cosmetic.globalSelectors, { attribute: family.attribute })
    )),
    ...groups[0].cosmetic.buckets.map((_, index) => writeFile(
      resolve(bucketsDirectory, `${cosmeticBucketName(index)}.json`),
      `${JSON.stringify({
        formatVersion: 1,
        bucket: cosmeticBucketName(index),
        groups: Object.fromEntries(groups.map(({ group, cosmetic }) => [group.id, cosmetic.buckets[index].domains]))
      })}\n`
    ))
  ]);
}

async function writeCosmeticArtifacts(compiled) {
  const cosmeticDirectory = resolve(rulesDirectory, "cosmetic");
  const bucketsDirectory = resolve(cosmeticDirectory, "buckets");
  await mkdir(bucketsDirectory, { recursive: true });
  await Promise.all([
    writeFile(
      resolve(contentDirectory, "compiled-cosmetic.css"),
      renderCompiledCosmeticCss(compiled.globalSelectors)
    ),
    writeFile(resolve(cosmeticDirectory, "metadata.json"), `${JSON.stringify({
      formatVersion: compiled.formatVersion,
      bucketCount: compiled.bucketCount,
      globalSelectors: compiled.globalSelectors.length,
      domainSelectors: compiled.domainSelectors,
      exceptionSelectors: compiled.exceptionSelectors
    }, null, 2)}\n`),
    ...compiled.buckets.map((bucket) => writeFile(
      resolve(bucketsDirectory, `${bucket.bucket}.json`),
      `${JSON.stringify(bucket)}\n`
    ))
  ]);
}

const [trackerSource, minerSource] = await Promise.all([read("tracker-domains.txt"), read("cryptomining-domains.txt")]);
const trackerDomains = parseDomainList(trackerSource);
const minerDomains = parseDomainList(minerSource);

// The ad lists' network rules come from each list without its sub-lists, as
// the extension's 12-hour downloads compile them (their dynamic-rule budget
// has no room for more); page cleanup and page scripts, which only releases
// update, use the full lists.
const privacySources = await Promise.all(PRIVACY_SOURCES.map(async (source) => ({ ...source, ...await readList(source) })));
const listTexts = privacySources.map((source) => source.text);
const fullListTexts = privacySources.map((source) => source.fullText);

// The ad and tracker lists compile through the same code the service worker
// uses for runtime list updates.
const compiledLists = compilePrivacyLists(privacySources, { starterDomains: new Set([...trackerDomains, ...minerDomains]) });
const {
  expandedRules: expandedPrivacyRules,
  semanticRules: semanticPrivacyRules,
  exceptionRules: privacyExceptionRules,
  popupHosts
} = compiledLists;
const compiledSource = (id) => compiledLists.sources.find((source) => source.id === id);

// YouTube replaces the player with an "Ad blockers violate YouTube's Terms of Service"
// wall when it detects that its ad pipeline was blocked. README, THREAT_MODEL, and
// AUDIT all state that Velor does not block YouTube video ads — but the global
// third-party ad-host lists blocked doubleclick, googlesyndication, and
// googleadservices on YouTube pages too, so the documented posture was not the
// shipped behavior and YouTube saw a blocked pipeline. This single packaged allow rule
// keeps those hosts reachable only when the page itself is YouTube. It sits above the
// privacy blocks (100-230) and below the threat blocks (1000-1100), so malware and
// phishing are still stopped on YouTube, and the same hosts stay blocked everywhere else.
const YOUTUBE_PAGE_DOMAINS = Object.freeze([
  "youtu.be",
  "youtube-nocookie.com",
  "youtube.com",
  "youtubekids.com"
]);
const YOUTUBE_AD_PIPELINE_HOSTS = Object.freeze([
  "2mdn.net",
  "doubleclick.net",
  "googleadservices.com",
  "googlesyndication.com",
  "googletagservices.com"
]);
const youtubePipelineExemption = {
  id: 900_001,
  priority: 500,
  action: { type: "allow" },
  condition: {
    requestDomains: [...YOUTUBE_AD_PIPELINE_HOSTS],
    initiatorDomains: [...YOUTUBE_PAGE_DOMAINS],
    resourceTypes: [...NETWORK_RESOURCE_TYPES]
  }
};

const privacyRules = [
  youtubePipelineExemption,
  ...compileDomainRules(trackerDomains, {
    startId: 1,
    priority: 100,
    thirdPartyOnly: true,
    resourceTypes: NETWORK_RESOURCE_TYPES
  }),
  ...compileDomainRules(minerDomains, {
    startId: 10_001,
    priority: 200,
    thirdPartyOnly: true,
    resourceTypes: NETWORK_RESOURCE_TYPES
  })
];

const feedRecords = {};
const feedMetadata = {};
for (const feed of THREAT_FEEDS) {
  const [source, metadataText] = await Promise.all([read(feed.file), read(feed.metadataFile)]);
  const metadata = JSON.parse(metadataText);
  if (metadata.sha256 !== sha256(source) || metadata.source !== feed.url) throw new Error(`${feed.id} provenance mismatch.`);
  feedRecords[feed.id] = { domains: parseThreatFeed(source, feed), updatedAt: metadata.fetchedAt };
  feedMetadata[feed.id] = metadata;
}
// One compile keeps attribution priority consistent; required feeds are
// unaffected by the optional gambling feed, which lands in its own ruleset.
const compiledThreats = compileThreatFeeds(feedRecords);
const feedById = (id) => THREAT_FEEDS.find((feed) => feed.id === id);
const rulesForRuleset = (rulesetId) => compiledThreats.sources
  .filter((source) => feedById(source.id).ruleset === rulesetId)
  .flatMap((source) => compiledThreats.rules.filter((rule) => rule.id >= source.ruleIdStart && rule.id <= source.ruleIdEnd));
const threatRules = rulesForRuleset("threat_protection");
const gamblingRules = rulesForRuleset("gambling_protection");
const threatSources = compiledThreats.sources.map((source) => ({
  ...feedMetadata[source.id], ...source,
  license: feedMetadata[source.id].license || feedMetadata[source.id].usage,
  entries: feedRecords[source.id].domains.length,
  ruleset: feedById(source.id).ruleset, optional: feedById(source.id).optional
}));
const requiredSources = threatSources.filter((source) => !source.optional);
const gamblingSources = threatSources.filter((source) => source.ruleset === "gambling_protection");
await mkdir(resolve(rulesDirectory, "threat-feeds"), { recursive: true });
await mkdir(contentDirectory, { recursive: true });
for (const feed of THREAT_FEEDS) await writeJson(`threat-feeds/${feed.id}.json`, feedRecords[feed.id]);
await writeFile(resolve(projectRoot, "extension/lib/threat-ranges.js"),
  `// Generated from reviewed snapshots by compile-rules.mjs.
export const PACKAGED_THREAT_SOURCES = Object.freeze(${JSON.stringify(threatSources, null, 2)});
`);
const cleanupSource = await read("adguard-url-tracking.txt");
const cleanupMetadata = JSON.parse(await read("adguard-url-tracking-source.json"));
if (sha256(cleanupSource) !== cleanupMetadata.sha256) throw new Error("AdGuard URL Tracking provenance mismatch.");
const cleanup = compileUrlCleanup(cleanupSource);

const cosmeticRules = compileConservativeCosmeticRules(fullListTexts);

// Optional lists (annoyance groups and regional lists) compile one at a time
// and on their own, so one list's exceptions never remove another's or the ad
// lists' rules (at run time its allow rules apply to every list, as in uBlock
// Origin). Block rules are numbered from 1 and list exceptions from
// OPTIONAL_ALLOW_START, so a matched rule's ID says whether it blocked. No
// page script may write a consent answer (optionalScriptletAllowed).
const OPTIONAL_FAMILIES = [
  // Annoyances keep working in Brave companion mode: data-velor-cosmetic.
  { id: "annoyances", groups: ANNOYANCE_GROUPS, attribute: "data-velor-cosmetic" },
  // Regional lists are ad lists, off in companion mode like the others.
  { id: "regional", groups: REGIONAL_LISTS, attribute: "data-velor-list-cosmetic" }
];
async function compileOptionalGroup(group) {
  // Packaged only, so every part uses the full list.
  const sources = await Promise.all(group.sources.map(async (source, index) => {
    const { fullText, metadata } = await readList(source);
    return { ...source, startId: index * 100_000 + 1, text: fullText, metadata };
  }));
  const network = compilePrivacyLists(sources, { starterDomains: new Set() });
  const blocks = [...network.expandedRules, ...network.semanticRules];
  if (blocks.length >= OPTIONAL_ALLOW_START) throw new Error(`${group.id} has too many block rules.`);
  return {
    group,
    sources,
    blockRules: blocks.length,
    rules: [
      ...blocks.map((rule, index) => ({ ...rule, id: index + 1 })),
      ...network.exceptionRules.map((rule, index) => ({ ...rule, id: OPTIONAL_ALLOW_START + index }))
    ],
    domains: network.sources.reduce((sum, source) => sum + source.domains.length, 0),
    cosmetic: compileConservativeCosmeticRules(sources.map((source) => source.text)),
    scriptlets: compileScriptletTables(
      sources.map((source) => ({ text: source.text, trusted: source.trusted })),
      { resolve: scriptletFor, skipHosts: PROTECTED_PLAYER_ROOTS, allow: (canonical, args) => optionalScriptletAllowed(group.id, canonical, args) }
    )
  };
}
const optionalFamilies = [];
for (const family of OPTIONAL_FAMILIES) {
  const groups = [];
  for (const group of family.groups) groups.push(await compileOptionalGroup(group));
  optionalFamilies.push({ family, groups });
}
const optionalGroupMetadata = ({ group, sources, rules, blockRules, domains, cosmetic, scriptlets: compiled }) => ({
  id: group.id,
  setting: group.setting,
  ruleset: group.ruleset,
  rules: rules.length,
  blockRules,
  domains,
  genericSelectors: cosmetic.globalSelectors.length,
  siteSelectors: cosmetic.domainSelectors,
  exceptionSelectors: cosmetic.exceptionSelectors,
  scriptletCalls: compiled.stats.calls,
  scriptletSites: compiled.stats.sites,
  rejected: { cosmetic: cosmetic.rejected, scriptlets: compiled.rejected },
  sources: sources.map(({ id, metadata }) => ({
    id,
    publisher: metadata.publisher,
    title: metadata.title,
    source: metadata.source,
    license: metadata.license,
    licenseUrl: metadata.licenseUrl,
    fetchedAt: metadata.fetchedAt,
    upstreamVersion: metadata.upstreamVersion,
    upstreamLastModified: metadata.upstreamLastModified,
    sha256: metadata.sha256
  }))
});
const optionalPolicy = { packaged: true, separateGroups: true, clicksConsent: false, writesConsent: false, allowRuleIdStart: OPTIONAL_ALLOW_START };
// uBlock Origin and AdGuard run their trusted-* scriptlets only from their own
// lists; Velor does the same. YouTube's own hosts keep Velor's documented
// posture: no page scripts there.
const TRUSTED_SCRIPTLET_SOURCES = new Set(["adguard-base", "ublock-filters", "ublock-privacy", "ublock-unbreak", "ublock-quick-fixes"]);
const scriptlets = compileScriptletTables(
  privacySources.map((source) => ({ text: source.fullText, trusted: TRUSTED_SCRIPTLET_SOURCES.has(source.id) })),
  { resolve: scriptletFor, skipHosts: PROTECTED_PLAYER_ROOTS }
);

async function writePageScriptFile(file, compiled) {
  const scripts = await Promise.all(compiled.scriptlets.map(async (canonical) => {
    const { fn, helpers, resource } = scriptletFor(canonical);
    return resource
      ? { canonical, source: await readFile(resolve(projectRoot, "extension/redirects", resource), "utf8") }
      : { canonical, fn, helpers };
  }));
  await writeFile(resolve(projectRoot, "extension", file), renderPageScriptFile({ scripts, calls: compiled.calls, table: compiled.table }));
}

async function writeScriptletArtifacts() {
  const directory = resolve(projectRoot, "extension/scriptlets/generated");
  await rm(directory, { recursive: true, force: true });
  await mkdir(directory, { recursive: true });
  // One registration for every site; the file looks the page up itself.
  // Each optional list with page scripts adds its own, registered while the
  // list is on.
  const excludeMatches = siteExcludeMatches(PROTECTED_PLAYER_ROOTS);
  const index = [{ id: "page-scripts", file: "scriptlets/generated/page-scripts.js", matches: ["*://*/*"], excludeMatches }];
  const files = [[index[0].file, scriptlets]];
  for (const { family, groups } of optionalFamilies) {
    for (const { group, scriptlets: compiled } of groups) {
      if (compiled.stats.calls === 0) continue;
      const file = `scriptlets/generated/${family.id}-${group.id}.js`;
      index.push({ id: `${family.id}-${group.id}`, group: group.id, file, matches: ["*://*/*"], excludeMatches });
      files.push([file, compiled]);
    }
  }
  await Promise.all(files.map(([file, compiled]) => writePageScriptFile(file, compiled)));
  await writeFile(resolve(directory, "index.json"), `${JSON.stringify(index)}\n`);
}

const sourceDates = requiredSources.map((source) => source.fetchedAt)
  .filter((value) => Number.isFinite(Date.parse(value))).sort();
const oldestSourceDate = sourceDates[0] || null;
const sumDomains = (sources) => sources.reduce((sum, source) => sum + source.domains, 0);

for (const { family } of optionalFamilies) {
  await rm(resolve(rulesDirectory, family.id), { recursive: true, force: true });
  await mkdir(resolve(rulesDirectory, family.id), { recursive: true });
}
await Promise.all([
  writeCosmeticArtifacts(cosmeticRules),
  ...optionalFamilies.map(writeOptionalCosmeticArtifacts),
  writeScriptletArtifacts(),
  ...optionalFamilies.flatMap(({ family, groups }) => groups.map(({ group, rules }) => writeJson(`${family.id}/${group.id}.json`, rules))),
  writeJson("privacy.json", privacyRules),
  writeJson("expanded-privacy.json", expandedPrivacyRules),
  writeJson("semantic-privacy.json", semanticPrivacyRules),
  writeJson("privacy-exceptions.json", privacyExceptionRules),
  writeFile(resolve(rulesDirectory, "popup-hosts.json"), `${JSON.stringify(popupHosts)}\n`),
  writeJson("threats.json", threatRules),
  writeJson("gambling.json", gamblingRules),
  writeJson("url-cleaning.json", cleanup.rules),
  writeJson("metadata.json", {
    formatVersion: 5,
    builtAt: new Date().toISOString(),
    urlCleanup: { ...cleanupMetadata, accepted: cleanup.accepted, rejected: cleanup.rejected, exceptions: cleanup.exceptions, rules: cleanup.rules.length, localParams: 24, droppedForBudget: cleanup.droppedForBudget, regexBudget: cleanup.regexBudget },
    privacy: {
      trackerDomains: trackerDomains.length,
      cryptominingDomains: minerDomains.length,
      rules: privacyRules.length,
      sourceSha256: sha256(`${trackerSource}\n${minerSource}`),
      expanded: {
        domains: expandedPrivacyRules.reduce((sum, rule) => sum + rule.condition.requestDomains.length, 0),
        easyListDomains: compiledSource("easylist").domains.length,
        easyPrivacyDomains: compiledSource("easyprivacy").domains.length,
        rules: expandedPrivacyRules.length,
        derivativeLicense: "GPL-3.0 (EasyList and EasyPrivacy under their GPLv3+ option)",
        attribution: privacySources.map((source) => source.metadata.publisher).join("; "),
        exceptionDomains: compiledLists.exceptions.excludedDomains.length,
        sourceSha256: sha256(listTexts.join("\n")),
        compilerPolicy: {
          exactDomainAnchorsOnly: true,
          thirdPartyOnly: true,
          mainFrameBlocking: false,
          acceptedOptions: ["important", "third-party", "3p"],
          exceptionsCompiledToAllowRules: true,
          unconvertibleExceptionRemovesHost: true,
          crossListExceptions: true,
          parentCoversSubdomains: true
        },
        semantic: {
          rules: semanticPrivacyRules.length,
          easyListRules: compiledSource("easylist").semanticRules.length,
          easyPrivacyRules: compiledSource("easyprivacy").semanticRules.length,
          acceptedFilters: compiledLists.sources.reduce((sum, source) => sum + source.acceptedFilters, 0),
          compilerPolicy: {
            hostAnchoredPaths: true,
            resourceTypes: true,
            firstThirdParty: true,
            initiatorDomains: true,
            matchCase: true,
            mainFrameBlocking: false,
            remoteAllowRules: false,
            ambiguousExceptionsRejected: true
          },
          rejected: Object.fromEntries(compiledLists.sources.map((source) => [source.id, source.rejected]))
        },
        popupHosts: popupHosts.length,
        scriptlets: {
          scripts: scriptlets.scriptlets.length,
          hosts: scriptlets.stats.sites,
          entities: scriptlets.stats.entities,
          calls: scriptlets.stats.calls,
          youtubeExcluded: true,
          rejected: scriptlets.rejected
        },
        exceptions: {
          rules: privacyExceptionRules.length,
          priority: 190,
          unconvertible: compiledLists.exceptions.unconvertible.length,
          rejected: compiledLists.exceptions.rejected
        },
        cosmetic: {
          globalSelectors: cosmeticRules.globalSelectors.length,
          domainSelectors: cosmeticRules.domainSelectors,
          exceptionSelectors: cosmeticRules.exceptionSelectors,
          parsedFilters: cosmeticRules.parsedFilters,
          sourceSha256: sha256(fullListTexts.join("\n")),
          compilerPolicy: {
            standardCssOnly: true,
            remoteScriptlets: false,
            genericSelectorBudget: 6000,
            siteSelectorBudget: MAX_DOMAIN_COSMETIC_SELECTORS,
            siteSelectorsLoadedByHostnameBucket: true,
            genericSelectorsWithExceptionsSuppressed: true
          },
          rejected: cosmeticRules.rejected
        },
        sources: privacySources.map((source) => ({
          id: source.id,
          name: source.name,
          kind: source.kind,
          publisher: source.metadata.publisher,
          title: source.metadata.title,
          source: source.metadata.source,
          license: source.metadata.license,
          licenseUrl: source.metadata.licenseUrl,
          fetchedAt: source.metadata.fetchedAt,
          upstreamVersion: source.metadata.upstreamVersion,
          upstreamLastModified: source.metadata.upstreamLastModified,
          upstreamCommit: source.metadata.upstreamCommit,
          sha256: source.metadata.sha256,
          compiledDomains: compiledSource(source.id).domains.length,
          semanticRules: compiledSource(source.id).semanticRules.length
        }))
      }
    },
    annoyances: { compilerPolicy: optionalPolicy, groups: optionalFamilies[0].groups.map(optionalGroupMetadata) },
    regional: { compilerPolicy: optionalPolicy, lists: optionalFamilies[1].groups.map(optionalGroupMetadata) },
    threats: {
      // Counts describe the always-on threat_protection ruleset; the optional
      // gambling ruleset is reported separately.
      domains: sumDomains(requiredSources),
      malwareDomains: sumDomains(requiredSources.filter((source) => source.category === "malware")),
      phishingDomains: sumDomains(requiredSources.filter((source) => source.category === "phishing")),
      rules: threatRules.length, fetchedAt: oldestSourceDate,
      gambling: { domains: sumDomains(gamblingSources), rules: gamblingRules.length, ruleset: "gambling_protection", enabledByDefault: false },
      sources: threatSources,
      protectedRejections: threatSources.reduce((sum, source) => sum + source.rejected.protected, 0)
    }
  })
]);

const enabledStaticRules = privacyRules.length + expandedPrivacyRules.length + semanticPrivacyRules.length
  + privacyExceptionRules.length + threatRules.length + cleanup.rules.length;
console.log(JSON.stringify({
  network_privacy: privacyRules.length, expanded_privacy: expandedPrivacyRules.length,
  semantic_privacy: semanticPrivacyRules.length, privacy_exceptions: privacyExceptionRules.length, threat_protection: threatRules.length,
  gambling_protection: gamblingRules.length, url_cleanup: cleanup.rules.length,
  optional: Object.fromEntries(optionalFamilies.flatMap(({ groups }) => groups.map(({ group, rules }) => [group.ruleset, rules.length]))),
  enabledByDefaultStaticRules: enabledStaticRules,
  totalStaticRules: enabledStaticRules + gamblingRules.length,
  feeds: threatSources.map(({ id, ruleset, domains, rules, rejected }) => ({ id, ruleset, domains, rules, rejected })),
  cleanup: { accepted: cleanup.accepted, rejected: cleanup.rejected, exceptions: cleanup.exceptions, droppedForBudget: cleanup.droppedForBudget, regexBudget: cleanup.regexBudget }
}, null, 2));
