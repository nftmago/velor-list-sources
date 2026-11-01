// Velor stand-in for Google Publisher Tag (gpt.js). Pages get the command
// queue, services and slot objects they expect, but no ad is ever requested
// and no slot event (slotRenderEnded and friends) ever fires.
(function () {
  "use strict";
  const existing = window.googletag;
  if (existing && existing.apiReady) return;
  const googletag = existing && typeof existing === "object" ? existing : (window.googletag = {});
  const queued = Array.isArray(googletag.cmd) ? googletag.cmd.slice() : [];
  const VERSION = "2026102701";

  function run(fn) {
    if (typeof fn !== "function") return;
    // A failing page callback must not stop the rest of the queue.
    try { fn(); } catch {}
  }
  function chain(target, names) {
    for (const name of names) target[name] = function () { return target; };
    return target;
  }
  function targetable(target) {
    const map = new Map();
    target.setTargeting = function (key, value) { map.set(String(key), [].concat(value).map(String)); return target; };
    target.getTargeting = (key) => map.get(String(key)) || [];
    target.getTargetingKeys = () => [...map.keys()];
    target.getTargetingMap = () => Object.fromEntries(map);
    target.clearTargeting = function (key) { if (key === undefined) map.clear(); else map.delete(String(key)); return target; };
    return target;
  }

  const slots = [];
  let slotCount = 0;
  let initialLoadDisabled = false;

  function service(name) {
    return chain({
      removeEventListener() {},
      getName: () => name,
      getSlots: () => slots.slice(),
      getSlotIdMap: () => Object.fromEntries(slots.map((slot) => [slot.getSlotId().getId(), slot])),
      getAttributeKeys: () => [],
      get: () => null
    }, ["addEventListener", "set", "enable"]);
  }

  function defineSlot(path, sizes, elementId, outOfPage) {
    const id = `${path}_${slotCount++}`;
    const services = [];
    const slotId = { getAdUnitPath: () => path, getDomId: () => elementId || "", getId: () => id, getName: () => id };
    const slot = targetable({
      addService(target) { if (!services.includes(target)) services.push(target); return slot; },
      getServices: () => services.slice(),
      getAdUnitPath: () => path,
      getSlotElementId: () => elementId || "",
      getSlotId: () => slotId,
      getName: () => id,
      getSizes() {
        if (!Array.isArray(sizes)) return [];
        const list = typeof sizes[0] === "number" ? [sizes] : sizes;
        return list.map((size) => Array.isArray(size) ? { getWidth: () => size[0], getHeight: () => size[1] } : size);
      },
      getOutOfPage: () => Boolean(outOfPage),
      getResponseInformation: () => null,
      getCollapseEmptyDiv: () => null,
      getDivStartsCollapsed: () => null,
      getCategoryExclusions: () => [],
      getAttributeKeys: () => [],
      get: () => null,
      getConfig: () => ({}),
      getHtml: () => "",
      getContentUrl: () => "",
      getClickUrl: () => "",
      getEscapedQemQueryId: () => "",
      getFirstLook: () => 0
    });
    chain(slot, ["clearCategoryExclusions", "defineSizeMapping", "set", "setCategoryExclusion", "setClickUrl", "setCollapseEmptyDiv",
      "setConfig", "setForceSafeFrame", "setSafeFrameConfig", "updateTargetingFromMap"]);
    slots.push(slot);
    return slot;
  }

  const pubads = targetable(service("publisher_ads"));
  Object.assign(pubads, {
    disableInitialLoad() { initialLoadDisabled = true; },
    isInitialLoadDisabled: () => initialLoadDisabled,
    enableSingleRequest: () => true,
    enableAsyncRendering: () => true,
    enableSyncRendering: () => false,
    collapseEmptyDivs: () => true,
    clear: () => true,
    refresh() {},
    display() {},
    getCorrelator: () => "",
    getTagSessionCorrelator: () => 0,
    getVersion: () => VERSION,
    getVideoContent: () => null,
    getImaContent: () => null,
    isAdRequestFinished: () => true,
    isSlotAPersistentRoadblock: () => false,
    definePassback: (path, sizes) => defineSlot(path, sizes, "", false),
    defineOutOfPagePassback: (path) => defineSlot(path, undefined, "", true)
  });
  chain(pubads, ["clearCategoryExclusions", "clearTagForChildDirectedTreatment", "enableLazyLoad", "enableVideoAds", "forceExperiment", "markAsAmp",
    "setCategoryExclusion", "setCentering", "setCookieOptions", "setForceSafeFrame", "setImaContent", "setLocation", "setPrivacySettings",
    "setPublisherProvidedId", "setRequestNonPersonalizedAds", "setSafeFrameConfig", "setTagForChildDirectedTreatment", "setTagForUnderAgeOfConsent",
    "setVideoContent", "updateCorrelator"]);

  const companionAds = Object.assign(service("companion_ads"), { isRoadblockingSupported: () => false, isSlotAPersistentRoadblock: () => false });
  chain(companionAds, ["setRefreshUnfilledSlots", "setClearUnfilledSlots", "enableSyncLoading", "refreshAllSlots", "notifyUnfilledSlots", "fillSlot"]);
  const content = Object.assign(service("content"), { setContent() {} });
  const signalProviders = { push() {}, clearAllCache() {} };

  const cmd = [];
  cmd.push = function () { for (const fn of arguments) run(fn); return arguments.length; };

  Object.assign(googletag, {
    apiReady: true,
    pubadsReady: true,
    _loaded_: true,
    cmd,
    enums: Object.freeze({
      OutOfPageFormat: Object.freeze({ TOP_ANCHOR: 2, BOTTOM_ANCHOR: 3, REWARDED: 4, INTERSTITIAL: 5, LEFT_SIDE_RAIL: 6, RIGHT_SIDE_RAIL: 7, GAME_MANUAL_INTERSTITIAL: 8 }),
      TrafficSource: Object.freeze({ PURCHASED: 1, ORGANIC: 2 })
    }),
    secureSignalProviders: signalProviders,
    encryptedSignalProviders: signalProviders,
    getVersion: () => VERSION,
    pubads: () => pubads,
    companionAds: () => companionAds,
    content: () => content,
    defineSlot: (path, sizes, elementId) => defineSlot(path, sizes, elementId, false),
    defineOutOfPageSlot: (path, target) => defineSlot(path, undefined, typeof target === "string" ? target : "", true),
    destroySlots(list) {
      const doomed = Array.isArray(list) ? list : slots.slice();
      for (const slot of doomed) { const index = slots.indexOf(slot); if (index >= 0) slots.splice(index, 1); }
      return true;
    },
    display() {},
    enableServices() {},
    openConsole() {},
    setAdIframeTitle() {},
    setConfig() {},
    getConfig: () => ({}),
    sizeMapping() {
      const mapping = [];
      const builder = { addSize(viewport, sizes) { mapping.push([viewport, sizes]); return builder; }, build: () => mapping.slice() };
      return builder;
    }
  });
  queued.forEach(run);
})();
