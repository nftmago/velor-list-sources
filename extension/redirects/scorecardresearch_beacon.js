// Velor stand-in for the comScore beacon (scorecardresearch.com/beacon.js).
(function () {
  "use strict";
  function noop() {}
  const comscore = { beacon: noop, purge: noop };
  if (!window.COMSCORE || typeof window.COMSCORE.beacon !== "function") window.COMSCORE = comscore;
  const ns = window.ns_ = window.ns_ || {};
  ns.comScore = ns.comScore || window.COMSCORE;
  if (typeof window.udm_ !== "function") window.udm_ = noop;
})();
