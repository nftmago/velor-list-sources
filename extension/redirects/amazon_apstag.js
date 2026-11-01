// Velor stand-in for Amazon Publisher Services (apstag.js). The loader
// snippet's _Q backlog drains, init/fetchBids callbacks fire on the next tick
// with no bids, so pages fall through to their regular ad call.
(function () {
  "use strict";
  const existing = window.apstag;
  const queued = existing && Array.isArray(existing._Q) ? existing._Q.slice() : [];

  function later(fn, args) {
    if (typeof fn === "function") setTimeout(() => { try { fn.apply(null, args); } catch {} }, 0);
  }
  const apstag = {
    _Q: [],
    init(config, callback) { later(callback, []); },
    fetchBids(config, callback) { later(callback, [[], { hasErrors: false }]); },
    setDisplayBids() {},
    targetingKeys: () => [],
    renderImp() {},
    debug() {},
    dpa() {},
    rpa() {},
    upa() {}
  };
  function run(entry) {
    if (!Array.isArray(entry)) return;
    const method = entry[0] === "i" ? apstag.init : entry[0] === "f" ? apstag.fetchBids : null;
    if (method) method(...Array.from(entry[1] || []));
  }
  apstag._Q.push = function () { for (const entry of arguments) run(entry); return 0; };
  window.apstag = apstag;
  queued.forEach(run);
})();
