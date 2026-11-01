// Velor stand-in for Chartbeat (chartbeat.js): the pSUPERFLY API is inert.
(function () {
  "use strict";
  if (window.pSUPERFLY && typeof window.pSUPERFLY.virtualPage === "function") return;
  function noop() {}
  window.pSUPERFLY = { virtualPage: noop, activity: noop };
})();
