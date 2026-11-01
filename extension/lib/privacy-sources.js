import { parseAbpHeader } from "./abp-compiler.js";

// The ad and tracker lists, in attribution order: a host or path rule shared
// by several lists is credited to the first. Each list owns one 100,000-ID
// block in expanded_privacy and in semantic_privacy. A download must carry
// the list's title (or, for Peter Lowe's list, which has none, its homepage)
// and licence header, and a filter count (non-comment lines) within bounds.
const SOURCE_RANGE = 100_000;
export const MAX_PRIVACY_LIST_BYTES = 20 * 1024 * 1024;

export const UASSETS = Object.freeze({
  licenseHeader: "https://github.com/uBlockOrigin/uAssets/blob/master/LICENSE",
  publisher: "Raymond Hill and the uAssets contributors",
  license: "GPL-3.0",
  licenseUrl: "https://github.com/uBlockOrigin/uAssets/blob/master/LICENSE",
  attributionUrl: "https://github.com/uBlockOrigin/uAssets"
});
export const EASYLIST = Object.freeze({
  licenseHeader: "https://easylist.to/pages/licence.html",
  publisher: "The EasyList authors",
  license: "CC BY-SA 3.0 or GPLv3+",
  licenseUrl: "https://easylist.to/pages/licence.html",
  attributionUrl: "https://easylist.to/"
});
export const ADGUARD = Object.freeze({
  licenseHeader: "https://github.com/AdguardTeam/AdguardFilters/blob/master/LICENSE",
  publisher: "AdGuard",
  license: "GPL-3.0",
  licenseUrl: "https://github.com/AdguardTeam/AdguardFilters/blob/master/LICENSE",
  attributionUrl: "https://github.com/AdguardTeam/AdguardFilters"
});

export const PRIVACY_SOURCES = Object.freeze([
  { id: "easylist", name: "EasyList", kind: "ads", ...EASYLIST, title: "EasyList", url: "https://easylist.to/easylist/easylist.txt", minimumFilters: 40_000, maximumFilters: 200_000 },
  { id: "easyprivacy", name: "EasyPrivacy", kind: "trackers", ...EASYLIST, title: "EasyPrivacy", url: "https://easylist.to/easylist/easyprivacy.txt", minimumFilters: 30_000, maximumFilters: 200_000 },
  { id: "adguard-base", name: "AdGuard Base", kind: "ads", ...ADGUARD, title: "AdGuard Base filter", url: "https://filters.adtidy.org/extension/chromium/filters/2.txt", minimumFilters: 50_000, maximumFilters: 400_000 },
  {
    id: "peter-lowe",
    name: "Peter Lowe's list",
    kind: "ads",
    homepage: "https://pgl.yoyo.org/adservers/",
    metadataTitle: "Peter Lowe's ad and tracking server list",
    url: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=1&mimetype=plaintext",
    publisher: "Peter Lowe",
    license: "Free to combine with other lists and republish, with credit",
    licenseUrl: "https://pgl.yoyo.org/adservers/",
    attributionUrl: "https://pgl.yoyo.org/adservers/",
    minimumFilters: 1_000,
    maximumFilters: 20_000
  },
  { id: "ublock-filters", name: "uBlock filters", kind: "ads", ...UASSETS, title: "uBlock filters", url: "https://ublockorigin.github.io/uAssets/filters/filters.txt", minimumFilters: 3_000, maximumFilters: 60_000 },
  { id: "ublock-privacy", name: "uBlock Privacy", kind: "trackers", ...UASSETS, title: "uBlock filters – Privacy", url: "https://ublockorigin.github.io/uAssets/filters/privacy.txt", minimumFilters: 1_000, maximumFilters: 30_000 },
  { id: "ublock-unbreak", name: "uBlock Unbreak", kind: "fixes", ...UASSETS, title: "uBlock filters – Unbreak", url: "https://ublockorigin.github.io/uAssets/filters/unbreak.txt", minimumFilters: 1_000, maximumFilters: 30_000 },
  // Short-lived fixes the uBlock team ships within hours (the list expires
  // every 8). Its size swings with what is broken that week, so only the
  // bounds apply, not the size-jump guard.
  { id: "ublock-quick-fixes", name: "uBlock Quick fixes", kind: "fixes", ...UASSETS, title: "uBlock₀ filters – Quick fixes", url: "https://ublockorigin.github.io/uAssets/filters/quick-fixes.txt", minimumFilters: 50, maximumFilters: 10_000, jumpGuard: false }
].map((source, index) => Object.freeze({
  ...source,
  label: `${source.name} ${source.kind === "trackers" ? "tracker" : "ad"} protection`,
  startId: index * SOURCE_RANGE + 1
})));

export function privacySourceForRule(ruleId) {
  if (!Number.isSafeInteger(ruleId) || ruleId < 1) return null;
  return PRIVACY_SOURCES[Math.floor((ruleId - 1) / SOURCE_RANGE)] || null;
}

export function privacyListFilterCount(text) {
  return String(text || "").split(/\r?\n/).filter((line) => {
    const value = line.trim();
    return value && !value.startsWith("!") && !value.startsWith("[");
  }).length;
}

// Checks a downloaded list before it replaces the previous one: identity
// (title and licence header, title alone for lists whose header has no
// licence line, homepage, or a marker comment), filter-count bounds and,
// given the previous count, a 0.7x–1.3x change guard (unless the source opts
// out). Throws with the list id
// first; returns the count and the parsed header.
export function validatePrivacyListText(text, source, { previousFilters = 0, allowJump = false } = {}) {
  const header = parseAbpHeader(text);
  const identified = source.title
    ? header.title === source.title && (source.licenseHeader === null || header.license === source.licenseHeader)
    : source.homepage
      ? header.homepage === source.homepage
      : Boolean(source.marker) && String(text).slice(0, 2_000).includes(source.marker);
  if (!identified) throw new Error(`${source.id} update has an unexpected title, homepage or license header.`);
  const filters = privacyListFilterCount(text);
  if (filters < source.minimumFilters || filters > source.maximumFilters) {
    throw new Error(
      `${source.id} update rejected: ${filters} filters is outside `
      + `${source.minimumFilters}–${source.maximumFilters}.`
    );
  }
  if (!allowJump && source.jumpGuard !== false && previousFilters > 0 && (filters < previousFilters * 0.7 || filters > previousFilters * 1.3)) {
    throw new Error(
      `${source.id} update rejected: filter count changed from ${previousFilters} to ${filters}.`
    );
  }
  return { filters, header };
}
