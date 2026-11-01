// Velor stand-in for Universal Analytics (analytics.js). The command queue
// drains, trackers exist with stable fields, and hitCallback / ready
// callbacks fire on the next tick so navigation-after-tracking still happens.
(function () {
  "use strict";
  const name = window.GoogleAnalyticsObject || "ga";
  const existing = window[name];
  if (typeof existing === "function" && existing.loaded) return;
  const queued = existing && Array.isArray(existing.q) ? existing.q.slice() : [];
  const CLIENT_ID = "1000000000.1000000000";
  const trackers = new Map();

  function later(fn, args) {
    setTimeout(() => { try { fn.apply(null, args); } catch {} }, 0);
  }
  function tracker(trackingId, trackerName) {
    const fields = { trackingId, name: trackerName, clientId: CLIENT_ID, linkerParam: "", cookieDomain: "auto" };
    return {
      get: (field) => fields[field],
      set(field, value) { if (typeof field === "string") fields[field] = value; else Object.assign(fields, field); },
      send() {
        for (const arg of arguments) {
          if (arg && typeof arg === "object" && typeof arg.hitCallback === "function") { later(arg.hitCallback, []); return; }
        }
      }
    };
  }
  function create() {
    const args = Array.from(arguments);
    const strings = args.filter((arg) => typeof arg === "string");
    const options = Object.assign({}, ...args.filter((arg) => arg && typeof arg === "object"));
    const trackerName = strings[2] || options.name || "t0";
    const created = tracker(strings[0] || options.trackingId || "", trackerName);
    created.set(options);
    trackers.set(trackerName, created);
    return created;
  }
  function ga() {
    const args = Array.from(arguments);
    const command = args.shift();
    if (typeof command === "function") return later(command, [trackers.get("t0")]);
    if (typeof command !== "string") return;
    const match = /^(?:(\w+)\.)?(\w+)(?::\w+)?$/.exec(command);
    if (!match) return;
    const [, trackerName = "t0", method] = match;
    if (method === "create") return void create(...args);
    if (method === "remove") return void trackers.delete(trackerName);
    const target = trackers.get(trackerName) || (trackerName === "t0" ? create() : null);
    if (target && (method === "send" || method === "set")) target[method](...args);
  }

  Object.assign(ga, {
    loaded: true,
    l: (existing && existing.l) || Date.now(),
    create,
    getAll: () => [...trackers.values()],
    getByName: (trackerName) => trackers.get(trackerName),
    remove: (trackerName) => trackers.delete(trackerName)
  });
  window[name] = ga;
  for (const args of queued) ga(...args);
})();
