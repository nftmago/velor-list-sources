import { ADGUARD, EASYLIST } from "./privacy-sources.js";

// Optional annoyance lists, grouped by what people see rather than by
// publisher; each group is one switch in Settings, off by default. They come
// with Velor and update with its releases, not with the 12-hour downloads:
// most of what they do is page cleanup and page scripts, which only a release
// can change, and their network rules would not fit the dynamic-rule budget
// beside the ad lists.
//
// Cookie notices are hidden, never answered: lists that press Accept or Reject
// for you (uBlock's and AdGuard's cookie lists) are left out, and so are page
// scripts that answer for you by writing the site's consent record (see
// optionalScriptletAllowed in optional-lists.js).
//
// Each group compiles into its own static ruleset (off in the manifest), its
// own generic CSS file, its own page-script file and a section of the shared
// annoyance cosmetic buckets. `trusted` lists may run trusted-* page scripts,
// as in uBlock Origin and AdGuard, which allow them only from their own lists.
// Small lists skip the size-jump guard: a few dozen filters swing them past it.
const EASYLIST_MIRROR = "https://ublockorigin.github.io/uAssets/thirdparties";
const ADGUARD_FILTERS = "https://filters.adtidy.org/extension/chromium/filters";
const easylist = (id, title, file, minimumFilters, maximumFilters, extra = {}) => ({
  id, ...EASYLIST, title, url: `${EASYLIST_MIRROR}/${file}`, minimumFilters, maximumFilters, trusted: false, ...extra
});
const adguard = (id, title, filter, minimumFilters, maximumFilters) => ({
  id, ...ADGUARD, title, url: `${ADGUARD_FILTERS}/${filter}.txt`, minimumFilters, maximumFilters, trusted: true
});

export const ANNOYANCE_GROUPS = Object.freeze([
  {
    id: "cookies", setting: "hideCookieNotices", name: "Cookie notices",
    sources: [easylist("easylist-cookies", "EasyList – Cookie Notices", "easylist-cookies.txt", 10_000, 120_000)]
  },
  {
    id: "popups", setting: "hidePopupPrompts", name: "Pop-ups and sign-up boxes",
    sources: [
      adguard("adguard-popups", "AdGuard Popups filter", 19, 8_000, 100_000),
      easylist("easylist-newsletters", "EasyList – Newsletter Notices", "easylist-newsletters.txt", 2_000, 30_000),
      easylist("easylist-notifications", "EasyList – Notifications", "easylist-notifications.txt", 500, 10_000)
    ]
  },
  {
    id: "social", setting: "hideSocialWidgets", name: "Social media buttons",
    sources: [easylist("easylist-social", "EasyList – Social Widgets", "easylist-social.txt", 5_000, 60_000)]
  },
  {
    id: "widgets", setting: "hideChatWidgets", name: "Chat and help bubbles",
    sources: [
      adguard("adguard-widgets", "AdGuard Widgets filter", 22, 800, 15_000),
      easylist("easylist-chat", "EasyList – Chat Widgets", "easylist-chat.txt", 50, 3_000, { jumpGuard: false })
    ]
  },
  {
    id: "ai", setting: "hideAiWidgets", name: "AI assistants",
    sources: [easylist("easylist-ai", "EasyList – Anti AI Suggestions", "easylist-ai.txt", 50, 3_000, { jumpGuard: false })]
  },
  {
    id: "other", setting: "hideOtherAnnoyances", name: "Other annoyances",
    sources: [
      adguard("adguard-other", "AdGuard Other Annoyances filter", 21, 3_000, 40_000),
      adguard("adguard-app-banners", "AdGuard Mobile App Banners filter", 20, 1_500, 20_000),
      easylist("easylist-annoyances", "EasyList – Annoyances", "easylist-annoyances.txt", 1_500, 20_000)
    ]
  }
].map((group) => Object.freeze({
  ...group,
  ruleset: `annoyances_${group.id}`,
  sources: Object.freeze(group.sources.map((source) => Object.freeze({ ...source, name: source.title, kind: "annoyances", group: group.id })))
})));

export const ANNOYANCE_SOURCES = Object.freeze(ANNOYANCE_GROUPS.flatMap((group) => group.sources));
