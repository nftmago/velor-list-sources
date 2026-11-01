import { isPublicHostname } from "./domain-rules.js";

// These roots host unrelated customer/application content. A hostname-only
// conversion would be too broad even when an upstream path rule is sound.
export const SHARED_INFRASTRUCTURE_ROOTS = Object.freeze(new Set([
  "akamaized.net",
  "akamaihd.net",
  "amazonaws.com",
  "appspot.com",
  "azureedge.net",
  "azurestaticapps.net",
  "azurewebsites.net",
  "blogspot.com",
  "cdn.jsdelivr.net",
  "cloudflare.com",
  "cloudfront.net",
  "fastly.net",
  "firebaseapp.com",
  "glitch.me",
  "github.io",
  "githubusercontent.com",
  "googleapis.com",
  "googleusercontent.com",
  "gstatic.com",
  "herokuapp.com",
  "medium.com",
  "netlify.app",
  "ngrok.app",
  "ngrok.io",
  "notion.site",
  "onrender.com",
  "pages.dev",
  "tumblr.com",
  "unpkg.com",
  "vercel.app",
  "web.app",
  "weebly.com",
  "windows.net",
  "wixsite.com",
  "wordpress.com",
  "workers.dev"
]));

// YouTube's own player, ad-telemetry, and media endpoints. README, THREAT_MODEL, and
// AUDIT all state that Velor does not block YouTube player APIs or media hosts: it
// hides page placements and uses the Skip control YouTube itself offers. Upstream
// EasyList/EasyPrivacy lines that hit these hosts silently contradict that promise,
// and blocking an ad-playback confirmation ping is precisely the signal YouTube's
// anti-ad-block check looks for. Reject them at compile time rather than letting a
// list refresh reintroduce them. Third-party ad hosts loaded *by* YouTube (for
// example googlesyndication.com) are not YouTube endpoints and stay blocked.
export const PROTECTED_PLAYER_ROOTS = Object.freeze(new Set([
  "googlevideo.com",
  "youtu.be",
  "youtube-nocookie.com",
  "youtube.com",
  "youtubekids.com",
  "ytimg.com"
]));

export function isProtectedPlayerHost(hostname, roots = PROTECTED_PLAYER_ROOTS) {
  const value = String(hostname || "").toLowerCase();
  if (!value) return false;
  for (const root of roots) {
    if (value === root || value.endsWith(`.${root}`)) return true;
  }
  // youtube.googleapis.com and similar Google-hosted YouTube APIs.
  return /(^|\.)youtube[a-z0-9-]*\.googleapis\.com$/.test(value);
}

const SAFE_OPTIONS = new Set(["important", "third-party", "3p"]);
// Exceptions that only switch off cosmetic filtering, script injection or
// pop-up handling on a page never unblock a network request; neither do
// exceptions aimed at one modifier (a redirect, CSP or parameter removal).
const PAGE_EXCEPTION_OPTIONS = new Set([
  "cname", "content", "ehide", "elemhide", "extension", "generichide", "ghide", "jsinject", "popunder", "popup", "shide", "specifichide"
]);
const MODIFIER_EXCEPTION_OPTIONS = new Set([
  "cookie", "csp", "header", "permissions", "redirect", "redirect-rule", "removeheader", "removeparam", "replace", "stealth", "urlskip"
]);

export function isNetworkException(line) {
  const modifiers = (String(line).split("$")[1] || "").split(",")
    .map((option) => option.trim().toLowerCase().replace(/^~/, "").split("=")[0])
    .filter((option) => option && option !== "domain");
  if (modifiers.some((option) => MODIFIER_EXCEPTION_OPTIONS.has(option))) return false;
  return modifiers.length === 0 || !modifiers.every((option) => PAGE_EXCEPTION_OPTIONS.has(option));
}
const DOMAIN_RULE = /^(?<exception>@@)?\|\|(?<hostname>[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)\^(?:\$(?<options>[^\s]+))?$/i;
const ANCHORED_HOST = /^(?:@@)?\|\|(?<hostname>[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?:\^|\/|\$)/i;

function normalizedOptions(value) {
  if (!value) return [];
  return value.split(",").map((option) => option.trim().toLowerCase()).filter(Boolean);
}

function anchoredHostname(line) {
  const value = line.match(ANCHORED_HOST)?.groups?.hostname?.toLowerCase() || "";
  return isPublicHostname(value) ? value : "";
}

export function createExceptionIndex(domains) {
  const exact = new Set([...domains].filter(isPublicHostname));
  const ancestorsOfExceptions = new Set();
  for (const domain of exact) {
    const labels = domain.split(".");
    for (let index = 1; index < labels.length - 1; index += 1) {
      ancestorsOfExceptions.add(labels.slice(index).join("."));
    }
  }
  return { exact, ancestorsOfExceptions };
}

export function hasExceptionConflict(domain, index) {
  if (!isPublicHostname(domain)) return true;
  if (index.ancestorsOfExceptions.has(domain)) return true;
  const labels = domain.split(".");
  for (let offset = 0; offset < labels.length - 1; offset += 1) {
    if (index.exact.has(labels.slice(offset).join("."))) return true;
  }
  return false;
}

// Lists mark lines meant only for some blockers or browsers with `!#if
// <token>` … `!#else` … `!#endif` (uBlock Origin's and AdGuard's
// directives). Velor keeps the sections uBlock Origin Lite on Chromium keeps:
// it reads uBlock's filter syntax but has no HTML filtering, IP-address
// matching or user stylesheets. A token it does not know, or a compound
// condition, leaves its section out, as in uBlock Origin. Directive lines are
// dropped; every compiler reads lists through this.
const TRUE_CONDITIONS = new Set(["ext_ublock", "ext_ubol", "env_chromium", "env_mv3", "adguard_ext_chromium", "adguard_ext_opera"]);
const FALSE_CONDITIONS = /^(?:false|ext_abp|ext_devbuild|env_(?:edge|firefox|legacy|mobile|safari)|cap_(?:html_filtering|user_stylesheet|ipaddress)|adguard(?:_\w+)?)$/;

function conditionHolds(expression) {
  const negated = expression.startsWith("!");
  const token = (negated ? expression.slice(1) : expression).trim();
  if (TRUE_CONDITIONS.has(token)) return !negated;
  if (FALSE_CONDITIONS.test(token)) return negated;
  return false;
}

export function applyListConditions(source) {
  const text = String(source || "");
  if (!text.includes("!#if")) return text;
  const open = [];
  const kept = [];
  for (const line of text.split(/\r?\n/)) {
    const directive = /^!#(if|else|endif)\b\s*(.*)$/.exec(line.trim());
    if (directive?.[1] === "if") open.push(conditionHolds(directive[2].trim()));
    else if (directive?.[1] === "else") { if (open.length) open[open.length - 1] = !open[open.length - 1]; }
    else if (directive?.[1] === "endif") open.pop();
    else if (open.every(Boolean)) kept.push(line);
  }
  return kept.join("\n");
}

export function parseAbpHeader(source) {
  const fields = {};
  for (const rawLine of String(source || "").split(/\r?\n/).slice(0, 80)) {
    const match = rawLine.trim().match(/^!\s*([^:]+):\s*(.+?)\s*$/);
    if (!match) continue;
    fields[match[1].trim().toLowerCase()] = match[2].trim();
  }
  return {
    title: fields.title || "",
    version: fields.version || "",
    lastModified: fields["last modified"] || "",
    expires: fields.expires || "",
    commit: fields.commit || "",
    homepage: fields.homepage || "",
    license: fields.licence || fields.license || ""
  };
}

export function extractConservativeAbpDomains(source, options = {}) {
  const sharedRoots = options.sharedInfrastructureRoots || SHARED_INFRASTRUCTURE_ROOTS;
  // Off when exceptions are compiled into their own allow rules instead.
  const applyExceptions = options.applyExceptions !== false;
  const lines = String(source || "").split(/\r?\n/);
  const exceptions = new Set();
  const badfilters = new Set();

  // Any anchored exception or badfilter removes the entire hostname from this
  // deliberately narrow conversion. That loses some coverage, but cannot turn
  // a path/domain-scoped upstream exception into a global DNR block.
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("!") || line.startsWith("[") || line.startsWith("#")) continue;
    const hostname = anchoredHostname(line);
    if (!hostname) continue;
    if (line.startsWith("@@") && isNetworkException(line)) exceptions.add(hostname);
    if (/(?:^|,)badfilter(?:,|$)/i.test(line.split("$")[1] || "")) badfilters.add(hostname);
  }

  const candidates = new Set();
  const important = new Set();
  const exceptionIndex = createExceptionIndex(applyExceptions ? exceptions : []);
  const badfilterIndex = createExceptionIndex(badfilters);
  const rejected = {
    unsupportedShape: 0,
    unsupportedOptions: 0,
    invalidHostname: 0,
    exception: 0,
    badfilter: 0,
    sharedInfrastructure: 0,
    duplicate: 0
  };

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("!") || line.startsWith("[") || line.startsWith("#") || line.startsWith("@@")) {
      continue;
    }
    const match = line.match(DOMAIN_RULE);
    if (!match?.groups) {
      rejected.unsupportedShape += 1;
      continue;
    }
    const hostname = match.groups.hostname.toLowerCase();
    const ruleOptions = normalizedOptions(match.groups.options);
    if (!isPublicHostname(hostname)) {
      rejected.invalidHostname += 1;
      continue;
    }
    if (ruleOptions.some((option) => !SAFE_OPTIONS.has(option))) {
      rejected.unsupportedOptions += 1;
      continue;
    }
    if (hasExceptionConflict(hostname, exceptionIndex)) {
      rejected.exception += 1;
      continue;
    }
    if (hasExceptionConflict(hostname, badfilterIndex)) {
      rejected.badfilter += 1;
      continue;
    }
    if (sharedRoots.has(hostname)) {
      rejected.sharedInfrastructure += 1;
      continue;
    }
    if (candidates.has(hostname)) {
      rejected.duplicate += 1;
      continue;
    }
    candidates.add(hostname);
    if (ruleOptions.includes("important")) important.add(hostname);
  }

  return {
    domains: [...candidates].sort(),
    important: [...important].sort(),
    exceptions: [...exceptions].sort(),
    badfilters: [...badfilters].sort(),
    rejected,
    header: parseAbpHeader(source),
    totalLines: lines.length
  };
}

const POPUP_TRIGGERS = new Set(["popup", "all", "document", "doc"]);
const POPUP_OPTIONS = new Set([...POPUP_TRIGGERS, "third-party", "3p", "important"]);

// Hosts whose filters block them as pop-ups or whole pages (`||host^$popup`,
// `$document` or `$all`). Velor's list rules never block whole pages, so the
// service worker instead closes a pop-up tab that lands on one, even after a
// click. Any exception or badfilter naming the host keeps it off the list.
export function extractPopupHosts(sources) {
  const listed = new Set();
  const excluded = new Set();
  for (const source of sources) {
    for (const rawLine of String(source || "").split(/\r?\n/)) {
      const line = rawLine.trim();
      const match = line.match(/^(?<exception>@@)?\|\|(?<hostname>[a-z0-9.-]+)\^\$(?<options>[^\s]+)$/i);
      if (!match?.groups) continue;
      const hostname = match.groups.hostname.toLowerCase();
      const options = normalizedOptions(match.groups.options);
      if (!options.some((option) => POPUP_TRIGGERS.has(option))) continue;
      if (match.groups.exception || options.includes("badfilter")) excluded.add(hostname);
      else if (isPublicHostname(hostname) && options.every((option) => POPUP_OPTIONS.has(option))) listed.add(hostname);
    }
  }
  const index = createExceptionIndex(excluded);
  return [...listed].filter((hostname) => !hasExceptionConflict(hostname, index)).sort();
}
