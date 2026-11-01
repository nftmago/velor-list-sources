// Velor stand-in for Google Tag Manager (gtm.js) and gtag.js. The data layer
// stays a plain array; pushes carrying eventCallback / event_callback are
// answered on the next tick (no tags run, so eventTimeout never matters) and
// google_tag_manager exposes the usual container model.
(function () {
  "use strict";
  const src = (document.currentScript && document.currentScript.src) || "";
  const param = (key) => {
    const match = new RegExp(`[?&]${key}=([^&#]*)`).exec(src);
    return match ? decodeURIComponent(match[1]) : "";
  };
  const layerName = param("l") || "dataLayer";
  const containerId = param("id");
  const gtm = window.google_tag_manager = window.google_tag_manager || {};
  if (containerId && gtm[containerId]) return;
  const layer = Array.isArray(window[layerName]) ? window[layerName] : (window[layerName] = []);
  const backlog = layer.slice();
  const state = {};
  const model = {
    name: layerName,
    get: (key) => state[key],
    set(key, value) { state[key] = value; },
    reset() { for (const key of Object.keys(state)) delete state[key]; }
  };

  function later(fn, args) {
    setTimeout(() => { try { fn.apply(null, args); } catch {} }, 0);
  }
  function process(item) {
    if (!item || typeof item !== "object") return;
    if (Array.isArray(item) || Object.prototype.toString.call(item) === "[object Arguments]") {
      // gtag("event", name, { event_callback }) / gtag("get", target, field, callback)
      const args = Array.from(item);
      if (args[0] === "get" && typeof args[3] === "function") later(args[3], [undefined]);
      for (const arg of args) if (arg && typeof arg === "object" && typeof arg.event_callback === "function") later(arg.event_callback, []);
      return;
    }
    Object.assign(state, item);
    if (typeof item.eventCallback === "function") later(item.eventCallback, [containerId]);
  }

  const previousPush = layer.push;
  layer.push = function () {
    const length = previousPush.apply(layer, arguments);
    for (const item of arguments) process(item);
    return length;
  };
  gtm[layerName] = gtm[layerName] || { gtmDom: true, gtmLoad: true, subscribers: 0 };
  gtm[layerName].subscribers += 1;
  if (containerId) gtm[containerId] = { dataLayer: model, bootstrap: Date.now() };
  backlog.forEach(process);
})();
