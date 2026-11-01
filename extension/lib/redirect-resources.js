// Filter-list redirect resource names (uBlock Origin, AdGuard and ABP
// spellings) mapped to the stand-in files Velor ships in extension/redirects/.
// A name missing here is one Velor cannot serve faithfully, so the compiler
// must skip that filter rather than block the request; keeping the real
// script is safer than a stub that breaks the page.
//
// Deliberately unmapped: gemius, popads.net.js / popads.js, hd-main.js,
// sensors-analytics.js, amzn_ads.js, google-analytics.com/cx/api.js,
// monkeybroker.js, addthis_widget.js, ampproject_v0.js,
// doubleclick_instream_ad_status.js, noeval*.js, nobab*.js, click2load.html,
// 3x2(-transparent).png, and AdGuard's `prebid` (a Prebid.js/pbjs stub, not
// the prebid-ads canary) and `empty`.

const ALIASES = {
  "noop.js": ["noopjs", "abp-resource:blank-js"],
  "noop.txt": ["nooptext", "abp-resource:blank-text"],
  "noop.html": ["noopframe", "abp-resource:blank-html"],
  "noop.css": ["noopcss", "abp-resource:blank-css"],
  "noop.json": ["noopjson"],
  "1x1.gif": ["1x1-transparent.gif", "abp-resource:1x1-transparent-gif"],
  "2x2.png": ["2x2-transparent.png", "abp-resource:2x2-transparent-png"],
  "32x32.png": ["32x32-transparent.png", "abp-resource:32x32-transparent-png"],
  "noop-0.1s.mp3": ["noopmp3-0.1s", "abp-resource:blank-mp3"],
  "noop-1s.mp4": ["noopmp4-1s", "abp-resource:blank-mp4"],
  "noop-vast2.xml": ["noopvast-2.0"],
  "noop-vast3.xml": ["noopvast-3.0"],
  "noop-vast4.xml": ["noopvast-4.0"],
  "noop-vmap1.xml": ["noop-vmap1.0.xml", "noopvmap-1.0"],
  "googletagservices_gpt.js": ["googletagservices-gpt", "googletagservices.com/gpt.js"],
  "googlesyndication_adsbygoogle.js": ["googlesyndication-adsbygoogle", "googlesyndication.com/adsbygoogle.js"],
  "google-analytics_analytics.js": ["google-analytics", "google-analytics.com/analytics.js"],
  "google-analytics_ga.js": ["google-analytics-ga", "google-analytics.com/ga.js"],
  "googletagmanager_gtm.js": ["googletagmanager-gtm", "googletagmanager.com/gtm.js"],
  "amazon_apstag.js": ["amazon-apstag"],
  "google-ima.js": ["google-ima3"],
  "fingerprint2.js": ["fingerprintjs2"],
  "fingerprint3.js": ["fingerprintjs3"],
  "scorecardresearch_beacon.js": ["scorecardresearch-beacon", "scorecardresearch.com/beacon.js"],
  "chartbeat.js": ["static.chartbeat.com/chartbeat.js"],
  "prebid-ads.js": ["prebid-ads"],
  "outbrain-widget.js": ["widgets.outbrain.com/outbrain.js"],
  "nofab.js": ["fuckadblock.js-3.2.0", "prevent-fab-3.2.0"]
};

export const REDIRECT_RESOURCES = Object.freeze(Object.fromEntries(
  Object.entries(ALIASES).flatMap(([file, aliases]) => [file, ...aliases].map((name) => [name, file]))
));

// Resolves a `redirect=` value to the extension path the DNR rule should
// serve, or null when Velor has no stand-in. Accepts uBO's `name:priority`
// suffix (`noopjs:10`).
export function redirectPathFor(name) {
  if (typeof name !== "string") return null;
  const file = REDIRECT_RESOURCES[name.trim().toLowerCase().replace(/:\d+$/, "")];
  return file ? `/redirects/${file}` : null;
}
