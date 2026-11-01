// Velor stand-in for legacy Google Analytics (ga.js). _gaq commands drain
// against inert trackers; queued functions and hitCallbacks still run, and
// _link/_linkByPost still navigate because pages use them as the real link.
(function () {
  "use strict";
  if (window._gat && typeof window._gat._getTracker === "function") return;
  const gaq = Array.isArray(window._gaq) ? window._gaq : (window._gaq = []);
  const queued = gaq.splice(0);
  const trackers = new Map();

  function noop() {}
  function tracker(initialAccount, name) {
    let account = initialAccount || "";
    const known = {
      _setAccount(id) { account = id; },
      _getAccount: () => account,
      _getName: () => name,
      _getVersion: () => "5.7.2",
      _getLinkerUrl: (url) => url,
      _setCustomVar: () => true,
      _set(key, value) { if (key === "hitCallback" && typeof value === "function") setTimeout(value, 0); },
      _link(url) { if (typeof url === "string") location.assign(url); },
      _linkByPost(form) { if (form && typeof form.submit === "function") form.submit(); }
    };
    // Every other _method the real tracker exposes is a silent no-op.
    return new Proxy(known, {
      get: (target, property) => property in target ? target[property] : (typeof property === "string" && property.startsWith("_") ? noop : undefined)
    });
  }
  function trackerFor(name, account) {
    if (!trackers.has(name)) trackers.set(name, tracker(account, name));
    return trackers.get(name);
  }
  function execute(item) {
    if (typeof item === "function") { try { item(); } catch {} return; }
    if (!Array.isArray(item) || typeof item[0] !== "string") return;
    const dot = item[0].indexOf(".");
    const target = trackerFor(dot > 0 ? item[0].slice(0, dot) : "");
    try { target[item[0].slice(dot + 1)](...item.slice(1)); } catch {}
  }

  gaq.push = function () { for (const item of arguments) execute(item); return gaq.length; };
  gaq._getAsyncTracker = (name) => trackerFor(name || "");
  gaq._createAsyncTracker = (account, name) => { trackers.delete(name || ""); return trackerFor(name || "", account); };
  window._gat = {
    _getTracker: (account) => gaq._createAsyncTracker(account, ""),
    _createTracker: (account, name) => gaq._createAsyncTracker(account, name),
    _getTrackerByName: (name) => trackerFor(name || ""),
    _getTrackers: () => [...trackers.values()],
    _anonymizeIp: noop,
    _forceSSL: noop
  };
  queued.forEach(execute);
})();
