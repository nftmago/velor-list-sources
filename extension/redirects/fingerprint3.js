// Velor stand-in for FingerprintJS 3 (open source and Pro loaders). load()
// resolves to an agent whose get() always yields the same fixed visitorId.
(function () {
  "use strict";
  if (window.FingerprintJS && typeof window.FingerprintJS.load === "function") return;
  const VISITOR_ID = "ba5e1e55ba5e1e55ba5e1e55ba5e1e55";
  const result = () => ({ visitorId: VISITOR_ID, components: {}, confidence: { score: 0, comment: "" }, version: "3.4.2", visitorFound: false, requestId: "" });
  const agent = { get: () => Promise.resolve(result()) };
  window.FingerprintJS = {
    load: () => Promise.resolve(agent),
    hashComponents: () => VISITOR_ID,
    componentsToDebugString: (components) => JSON.stringify(components || {})
  };
})();
