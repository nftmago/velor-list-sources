// Page scripts run in the page's own world before its scripts, so they cannot
// ask Velor for the site's mode. The generated file is registered for every
// site and looks the page up in its own table; the build's exclusions
// (YouTube's hosts) and Off or paused sites are excluded from registration.
// `enabled` covers the ad lists' file; an annoyance group's file (an index
// entry with `group`) is registered while that group is in `groups`.
export const SCRIPTLET_ID_PREFIX = "velor-scriptlet-";

export function siteExcludeMatches(sites) {
  // `*.site` also matches the bare site in Chrome match patterns.
  return [...new Set(sites)].sort().map((site) => `*://*.${site}/*`);
}

export async function syncScriptletScripts({ scripting, enabled, groups = [], index, excludedSites }) {
  const registered = (await scripting.getRegisteredContentScripts())
    .filter((script) => script.id.startsWith(SCRIPTLET_ID_PREFIX));
  const siteExclusions = siteExcludeMatches(excludedSites);
  const desired = index.filter((entry) => (entry.group ? groups.includes(entry.group) : enabled)).map((entry) => ({
    id: `${SCRIPTLET_ID_PREFIX}${entry.id}`,
    js: [entry.file],
    matches: entry.matches,
    excludeMatches: [...new Set([...(entry.excludeMatches || []), ...siteExclusions])],
    runAt: "document_start",
    allFrames: true,
    world: "MAIN",
    persistAcrossSessions: true
  }));
  // Chrome reports patterns back sorted, so compare sorted copies.
  const sorted = (patterns = []) => JSON.stringify([...patterns].sort());
  const signature = (script) => JSON.stringify([script.id, script.js, sorted(script.matches)]);
  const current = new Map(registered.map((script) => [script.id, script]));
  const sameScripts = registered.length === desired.length
    && desired.every((script) => current.has(script.id) && signature(current.get(script.id)) === signature(script));
  if (sameScripts) {
    // Off/paused sites changed: update exclusions in place.
    const stale = desired.filter((script) => sorted(current.get(script.id).excludeMatches) !== sorted(script.excludeMatches));
    if (stale.length === 0) return false;
    await scripting.updateContentScripts(stale.map(({ id, excludeMatches }) => ({ id, excludeMatches })));
    return true;
  }
  if (registered.length > 0) await scripting.unregisterContentScripts({ ids: registered.map((script) => script.id) });
  if (desired.length > 0) await scripting.registerContentScripts(desired);
  return true;
}
