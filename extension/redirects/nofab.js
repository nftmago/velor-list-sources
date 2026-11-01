// Velor stand-in for FuckAdBlock / BlockAdBlock 3.2.0. The API is complete but
// the verdict is fixed: onNotDetected handlers run on the next tick (once per
// registration or check, coalesced), onDetected handlers never run.
(function () {
  "use strict";
  function FuckAdBlock(options) {
    this._options = Object.assign({}, options);
    this._notDetected = [];
    this._pending = false;
  }
  FuckAdBlock.prototype = {
    constructor: FuckAdBlock,
    _emit() {
      if (this._pending) return;
      this._pending = true;
      setTimeout(() => {
        this._pending = false;
        for (const fn of this._notDetected.slice()) { try { fn(); } catch {} }
      }, 0);
    },
    setOption(options, value) {
      if (typeof options === "string") this._options[options] = value;
      else Object.assign(this._options, options);
      return this;
    },
    check() { this._emit(); return false; },
    clearEvent() { this._notDetected = []; return this; },
    emitEvent(detected) { if (!detected) this._emit(); return this; },
    on(detected, fn) {
      if (!detected && typeof fn === "function") { this._notDetected.push(fn); this._emit(); }
      return this;
    },
    onDetected(fn) { return this.on(true, fn); },
    onNotDetected(fn) { return this.on(false, fn); }
  };

  window.FuckAdBlock = window.BlockAdBlock = FuckAdBlock;
  if (window.fuckAdBlock === undefined) window.fuckAdBlock = new FuckAdBlock({ checkOnLoad: true, resetOnEnd: true });
  if (window.blockAdBlock === undefined) window.blockAdBlock = new FuckAdBlock({ checkOnLoad: true, resetOnEnd: true });
})();
