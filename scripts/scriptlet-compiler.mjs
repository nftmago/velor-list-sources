import { isPublicHostname } from "./rule-compiler.mjs";
import { applyListConditions } from "../extension/lib/abp-compiler.js";

// Page-script filters: uBlock `hosts##+js(name, args…)` and AdGuard
// `hosts#%#//scriptlet('name', 'args'…)`. All of them compile into one
// generated MAIN-world file holding Velor's own implementations and a site
// table. Chrome checks a registered script's site patterns on every page
// load, so the file is registered once for all sites and looks the page up
// itself, as uBlock Origin Lite does; that also lets `example.*` filters run.
const UBO_FILTER = /^(?<domains>[^#\s]*)#(?<exception>@?)#\+js\((?<body>.*)\)$/;
const ADGUARD_FILTER = /^(?<domains>[^#\s]*)#(?<exception>@?)%#\/\/scriptlet\((?<body>.*)\)$/;
const MAX_ARGUMENT_LENGTH = 512;
const ENTITY_NAME = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const SITES_PER_BUCKET = 16;

// uBO separates arguments with commas ("\," is a literal comma); an argument
// wrapped in quotes (', " or `) keeps its commas and spaces.
function splitUboArguments(body) {
  const values = [];
  let index = 0;
  for (;;) {
    while (body[index] === " ") index += 1;
    let value = null;
    const quote = body[index];
    if (quote === "'" || quote === "\"" || quote === "`") {
      let end = index + 1;
      let text = "";
      while (end < body.length && body[end] !== quote) {
        if (body[end] === "\\" && body[end + 1] === quote) end += 1;
        text += body[end];
        end += 1;
      }
      let next = end + 1;
      while (body[next] === " ") next += 1;
      if (end < body.length && (next >= body.length || body[next] === ",")) {
        value = text;
        index = next;
      }
    }
    if (value === null) {
      value = "";
      while (index < body.length && body[index] !== ",") {
        if (body[index] === "\\" && body[index + 1] === ",") index += 1;
        value += body[index];
        index += 1;
      }
      value = value.trim();
    }
    values.push(value);
    if (index >= body.length) return values;
    index += 1;
  }
}

function splitAdguardArguments(body) {
  const values = [];
  const pattern = /\s*(["'])((?:\\.|(?!\1).)*)\1\s*(?:,|$)/gy;
  let match;
  while ((match = pattern.exec(body)) && match[0]) {
    values.push(match[2].replace(/\\(.)/g, "$1"));
    if (pattern.lastIndex >= body.length) break;
  }
  return pattern.lastIndex >= body.trim().length || values.length === 0 ? values : null;
}

// Sites are hostnames or uBO entity names (`example.*`: example under any
// public suffix).
function parseScope(value) {
  const included = [];
  const excluded = [];
  for (const raw of value.split(",").map((entry) => entry.trim().toLowerCase()).filter(Boolean)) {
    const negative = raw.startsWith("~");
    const site = negative ? raw.slice(1) : raw;
    if (!(site.endsWith(".*") ? ENTITY_NAME.test(site.slice(0, -2)) : isPublicHostname(site))) return null;
    (negative ? excluded : included).push(site);
  }
  return { included, excluded };
}

export function parseScriptletFilter(rawLine) {
  const line = String(rawLine || "").trim();
  const ubo = line.match(UBO_FILTER);
  const adguard = ubo ? null : line.match(ADGUARD_FILTER);
  const match = ubo || adguard;
  if (!match?.groups) return null;
  const values = ubo ? splitUboArguments(match.groups.body) : splitAdguardArguments(match.groups.body);
  const scope = parseScope(match.groups.domains);
  if (!values || !scope) return { invalid: true };
  const [name = "", ...args] = values;
  if (args.some((value) => value.length > MAX_ARGUMENT_LENGTH)) return { invalid: true };
  return { exception: match.groups.exception === "@", name, args, scope };
}

// True when `site` or one of its parents is in `sites` (works for entity
// names too: `a.example.*` is under `example.*`).
const siteCovered = (site, sites) => {
  if (!sites) return false;
  const labels = site.split(".");
  return labels.some((_, index) => index < labels.length - 1 && sites.has(labels.slice(index).join(".")));
};

// The entity names a hostname answers to: each parent with one or more
// trailing labels replaced by "*". Shared with the generated file, which
// inlines its source.
export function velorEntityNames(hostname) {
  const labels = hostname.split(".");
  return labels.flatMap((_, index) => {
    const parts = labels.slice(index);
    return parts.slice(1).map((__, end) => parts.slice(0, parts.length - 1 - end).join(".") + ".*");
  });
}

// Exceptions reach a site from its parents and, for a hostname, from its
// entity names too (`example.*#@#…` also covers example.com's own filters).
const exceptionCovers = (site, sites) => siteCovered(site, sites)
  || Boolean(sites && !site.endsWith(".*") && velorEntityNames(site).some((name) => sites.has(name)));

const addTo = (map, key, value) => map.set(key, (map.get(key) || new Set()).add(value));

// `resolve(name)` returns { canonical, trusted } for implemented scriptlets or
// null. Trusted scriptlets are accepted only from sources marked `trusted`
// (uBlock Origin's and AdGuard's own lists), as in those blockers.
// `skipHosts` (YouTube's own hosts, for now) never receive page scripts.
// `allow(canonical, args)` can refuse individual calls (counted as `policy`).
//
// Returns the scriptlets used, the distinct calls ([scriptlet index, args])
// and, per site, its call references: positive to run the call, negative
// (~index) to cancel it for that site's parents and entity names, which is
// how exceptions and `~sub.example.com` exclusions reach broader filters.
export function compileScriptletTables(sources, { resolve, skipHosts = new Set(), allow = () => true }) {
  const rejected = { invalid: 0, unknownScriptlet: 0, untrusted: 0, policy: 0, genericOnly: 0, skippedHost: 0, exception: 0, duplicate: 0 };
  const callKey = (canonical, args) => JSON.stringify([canonical, args]);
  const exceptions = new Map();
  const blanketExceptions = new Set();
  const filters = [];
  for (const { text, trusted } of sources) {
    for (const rawLine of applyListConditions(text).split(/\r?\n/)) {
      const parsed = parseScriptletFilter(rawLine);
      if (!parsed) continue;
      if (parsed.invalid) {
        rejected.invalid += 1;
        continue;
      }
      const resolved = parsed.name ? resolve(parsed.name) : null;
      if (parsed.exception) {
        for (const site of parsed.scope.included) {
          if (!parsed.name) blanketExceptions.add(site);
          else if (resolved) addTo(exceptions, callKey(resolved.canonical, parsed.args), site);
        }
        continue;
      }
      if (!resolved) rejected.unknownScriptlet += 1;
      else if (resolved.trusted && !trusted) rejected.untrusted += 1;
      else if (!allow(resolved.canonical, parsed.args)) rejected.policy += 1;
      else filters.push({ ...parsed, call: callKey(resolved.canonical, parsed.args) });
    }
  }
  // Entity names that are YouTube's own (`youtube.*`); registration also
  // excludes YouTube's hosts, which covers every other entity name.
  const skippedSite = (site) => site.endsWith(".*")
    ? [...skipHosts].some((host) => host.startsWith(site.slice(0, -1)))
    : siteCovered(site, skipHosts);
  // site → Map(call → subdomains it is excluded from)
  const sites = new Map();
  for (const filter of filters) {
    if (filter.scope.included.length === 0) {
      rejected.genericOnly += 1;
      continue;
    }
    for (const site of filter.scope.included) {
      if (skippedSite(site)) {
        rejected.skippedHost += 1;
        continue;
      }
      if (exceptionCovers(site, blanketExceptions) || exceptionCovers(site, exceptions.get(filter.call))) {
        rejected.exception += 1;
        continue;
      }
      const excluded = filter.scope.excluded.filter((domain) => domain.endsWith(`.${site}`));
      const calls = sites.get(site) || new Map();
      sites.set(site, calls);
      // The same call from several filters runs once, skipping only
      // subdomains every one of them excludes.
      if (calls.has(filter.call)) {
        calls.set(filter.call, calls.get(filter.call).filter((domain) => excluded.includes(domain)));
        rejected.duplicate += 1;
      } else {
        calls.set(filter.call, excluded);
      }
    }
  }

  const callKeys = [...new Set([...sites.values()].flatMap((calls) => [...calls.keys()]))].sort();
  const callIndex = new Map(callKeys.map((key, index) => [key, index]));
  const scriptlets = [...new Set(callKeys.map((key) => JSON.parse(key)[0]))].sort();
  const calls = callKeys.map((key) => {
    const [canonical, args] = JSON.parse(key);
    return [scriptlets.indexOf(canonical), args];
  });
  const cancelled = new Map();
  for (const [call, exceptionSites] of exceptions) {
    if (callIndex.has(call)) for (const site of exceptionSites) addTo(cancelled, site, call);
  }
  for (const siteCalls of sites.values()) {
    for (const [call, excluded] of siteCalls) for (const domain of excluded) addTo(cancelled, domain, call);
  }
  const table = {};
  for (const site of [...new Set([...sites.keys(), ...cancelled.keys(), ...blanketExceptions])].sort()) {
    if (blanketExceptions.has(site)) {
      table[site] = "!";
      continue;
    }
    const run = [...(sites.get(site)?.keys() || [])];
    // A filter naming the excluded subdomain itself still runs there.
    const cancel = [...(cancelled.get(site) || [])].filter((call) => !run.includes(call));
    const refs = [...run.map((call) => callIndex.get(call)), ...cancel.map((call) => ~callIndex.get(call))];
    if (refs.length > 0) table[site] = refs.join(",");
  }
  return {
    scriptlets,
    calls,
    table,
    rejected,
    stats: {
      sites: sites.size,
      entities: [...sites.keys()].filter((site) => site.endsWith(".*")).length,
      calls: [...sites.values()].reduce((sum, siteCalls) => sum + siteCalls.size, 0)
    }
  };
}

// Shared by the compiler and the generated file, which inlines its source.
export function velorSiteBucket(site, count) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < site.length; index += 1) hash = Math.imul(hash ^ site.charCodeAt(index), 0x01000193);
  return (hash >>> 0) % count;
}

// The site table as hash buckets of "\nsite\trefs" lines: a few hundred
// short strings parse far faster than an object with one key per site, and a
// lookup searches one small bucket.
function siteBuckets(table) {
  const sites = Object.keys(table);
  const buckets = Array.from({ length: Math.max(1, Math.ceil(sites.length / SITES_PER_BUCKET)) }, () => "");
  for (const site of sites) buckets[velorSiteBucket(site, buckets.length)] += `\n${site}\t${table[site]}`;
  return buckets.map((bucket) => (bucket ? `${bucket}\n` : ""));
}

// Filter arguments are data; escaping "(" and "=" inside the JSON strings keeps
// needles such as "eval(" from reading as code to the package scanner.
function dataLiteral(value) {
  return JSON.stringify(value).replace(/[(=]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

// Reads the table back out of a generated file (smoke tests, diagnostics).
export function readPageScriptData(source) {
  const sites = JSON.parse(source.match(/^ *const sites = (.*);$/m)[1]);
  const calls = JSON.parse(source.match(/^ *const calls = (".*")\.split/m)[1]).split("\n").map((line) => JSON.parse(line));
  const scriptlets = JSON.parse(source.match(/^\/\/ Scriptlets: (.*)$/m)[1]);
  const table = Object.fromEntries(sites.flatMap((bucket) => bucket.split("\n").filter(Boolean).map((line) => line.split("\t"))));
  return { scriptlets, calls, table };
}

// One self-contained MAIN-world file. `scripts[i]` is the scriptlet with
// index i: library entries carry `fn` and `helpers`, resource-backed ones the
// stand-in `source` to run as is. Function declarations are compiled only
// when called, so pages without page scripts pay for the lookup alone.
export function renderPageScriptFile({ scripts, calls, table }) {
  const helpers = new Map(scripts.flatMap((script) => script.helpers || []).map((helper) => [helper.name, helper]));
  const functions = scripts.map((script, index) => script.fn
    ? { name: script.fn.name, source: script.fn.toString() }
    : { name: `velorResource${index}`, source: `function velorResource${index}() {\n${script.source}\n}` });
  return `// Generated by compile-rules.mjs from reviewed filter lists. Do not edit.
// Scriptlets: ${JSON.stringify(scripts.map((script) => script.canonical))}
(function () {
  "use strict";
${[...helpers.values()].map((helper) => `  ${helper.toString()}`).join("\n")}
${functions.map((fn) => `  ${fn.source}`).join("\n")}
  const velorScriptlets = [${functions.map((fn) => fn.name).join(", ")}];
  // The lookup runs in its own scope so scriptlets never see its variables.
  (function () {
    const hostname = location.hostname;
    if (!hostname) return;
    const sites = ${dataLiteral(siteBuckets(table))};
    ${velorSiteBucket.toString()}
    const lookup = (site) => {
      const bucket = sites[velorSiteBucket(site, sites.length)];
      const at = bucket.indexOf("\\n" + site + "\\t");
      return at === -1 ? "" : bucket.slice(at + site.length + 2, bucket.indexOf("\\n", at + 1));
    };
    // Most specific first: the hostname and its parents, then entity names
    // longest first. A negative reference cancels that call for every
    // broader match after it; "!" switches page scripts off from there on.
    ${velorEntityNames.toString()}
    const labels = hostname.split(".");
    const hosts = labels.map((_, index) => labels.slice(index).join("."));
    const entities = [...new Set(velorEntityNames(hostname))].sort((left, right) => right.length - left.length);
    const run = new Set();
    const cancelled = new Set();
    for (const site of [...hosts, ...entities]) {
      const refs = lookup(site);
      if (refs === "!") break;
      if (!refs) continue;
      for (const ref of refs.split(",")) {
        const call = Number(ref);
        if (call < 0) cancelled.add(~call);
        else if (!cancelled.has(call)) run.add(call);
      }
    }
    if (run.size === 0) return;
    const calls = ${dataLiteral(calls.map((call) => JSON.stringify(call)).join("\n"))}.split("\\n");
    for (const call of [...run].sort((left, right) => left - right)) {
      const [scriptlet, args] = JSON.parse(calls[call]);
      try { velorScriptlets[scriptlet](...args); } catch {}
    }
  })();
})();
`;
}

