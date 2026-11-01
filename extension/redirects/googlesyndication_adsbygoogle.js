// Velor stand-in for AdSense (adsbygoogle.js). Each push consumes the next
// unprocessed <ins class="adsbygoogle"> the way the real loader does, marking
// it done and unfilled, so pages that wait on that status settle without an ad.
(function () {
  "use strict";
  const existing = window.adsbygoogle;
  if (existing && existing.loaded) return;
  const adsbygoogle = Array.isArray(existing) ? existing : (window.adsbygoogle = []);
  const queued = adsbygoogle.splice(0);

  function nextSlot() {
    for (const element of document.querySelectorAll("ins.adsbygoogle")) {
      if (!element.hasAttribute("data-adsbygoogle-status")) return element;
    }
    return null;
  }
  function handle(item) {
    if (typeof item === "function") { try { item(); } catch {} return; }
    if (item && item.enable_page_level_ads) return; // Auto ads request no slot.
    const element = nextSlot();
    if (!element) return;
    element.setAttribute("data-adsbygoogle-status", "done");
    element.setAttribute("data-ad-status", "unfilled");
  }

  adsbygoogle.push = function () { for (const item of arguments) handle(item); return adsbygoogle.length; };
  adsbygoogle.loaded = true;
  queued.forEach(handle);
})();
