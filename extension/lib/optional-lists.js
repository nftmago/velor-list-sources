import { ANNOYANCE_GROUPS } from "./annoyance-sources.js";
import { REGIONAL_LISTS } from "./regional-sources.js";

// The opt-in packaged lists: annoyance groups and regional lists. Each has its
// own static ruleset; group ids are unique across both, as page scripts and
// site buckets key on them.
export const OPTIONAL_GROUPS = Object.freeze([...ANNOYANCE_GROUPS, ...REGIONAL_LISTS]);

// Within an optional ruleset, list exceptions (allow rules) start here, so a
// matched rule's ID says whether it blocked.
export const OPTIONAL_ALLOW_START = 500_001;

export function optionalGroupForRuleset(rulesetId) {
  return OPTIONAL_GROUPS.find((group) => group.ruleset === rulesetId) || null;
}

// Page scripts that write something a site reads as the visitor's choice: a
// page variable, a cookie or a storage entry. EasyList's cookie list uses
// them to answer banners (`cookie_cat_marketing = true`, `CookieConsent =
// accepted`), so the Cookie notices group uses none of them except to switch
// a consent tool off with an empty value; every other optional list uses them
// except where the call names consent.
const STATE_WRITERS = new Set([
  "set-constant", "set-cookie", "set-cookie-reload", "set-local-storage-item", "set-session-storage-item",
  "trusted-set-constant", "trusted-set-cookie", "trusted-set-cookie-reload", "trusted-set-local-storage-item", "trusted-set-session-storage-item"
]);
const EMPTY_VALUES = new Set(["noopFunc", "undefined", "null", "{}", "[]", ""]);
const CONSENT_WORDS = /consent|cookie|gdpr|ccpa|cmp|tcf|didomi|onetrust|optanon|cookiebot|usercentrics|truste|quantcast|sourcepoint/i;

export function optionalScriptletAllowed(groupId, canonical, args) {
  if (!STATE_WRITERS.has(canonical)) return true;
  if (canonical.endsWith("set-constant") && EMPTY_VALUES.has(String(args[1] ?? ""))) return true;
  return groupId !== "cookies" && !CONSENT_WORDS.test(JSON.stringify(args));
}
