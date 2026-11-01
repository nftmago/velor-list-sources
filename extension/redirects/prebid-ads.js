// Velor stand-in for the "ads.js" style bait file anti-adblock checks load:
// it sets the flags those checks look for so the page believes ads ran.
(function () {
  "use strict";
  window.canRunAds = true;
  window.isAdBlockActive = false;
})();
