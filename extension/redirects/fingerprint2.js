// Velor stand-in for FingerprintJS 2. Every caller gets the same fixed hash
// and an empty component list, so the page proceeds without a fingerprint.
(function () {
  "use strict";
  if (window.Fingerprint2 && window.Fingerprint2.VERSION) return;
  const HASH = "ba5e1e55ba5e1e55ba5e1e55ba5e1e55";
  function later(fn, args) {
    if (typeof fn === "function") setTimeout(() => { try { fn.apply(null, args); } catch {} }, 0);
  }

  function Fingerprint2(options) { this.options = options || {}; }
  Fingerprint2.prototype.get = function (callback) { later(callback, [HASH, []]); return this; };
  Fingerprint2.get = function (options, callback) { later(typeof options === "function" ? options : callback, [[]]); };
  Fingerprint2.getV18 = function (options, callback) { later(typeof options === "function" ? options : callback, [HASH, []]); };
  Fingerprint2.getPromise = () => Promise.resolve([]);
  Fingerprint2.x64hash128 = () => HASH;
  Fingerprint2.VERSION = "2.1.4";
  window.Fingerprint2 = Fingerprint2;
})();
