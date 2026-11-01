// Velor stand-in for the Outbrain widget loader (outbrain.js). The OBR.extern
// API is inert and recommendation requests answer with no documents.
(function () {
  "use strict";
  if (window.OBR && window.OBR.extern && typeof window.OBR.extern.researchWidget === "function") return;
  function noop() {}
  window.OBR = {
    extern: {
      researchWidget: noop,
      renderSpaWidgets: noop,
      refreshWidget: noop,
      callRecs(options, callback) {
        if (typeof callback === "function") setTimeout(() => { try { callback({ doc: [] }); } catch {} }, 0);
      },
      callClick: noop,
      callWhatIs: noop,
      returnedError: noop,
      returnedHtmlData: noop,
      returnedIrdData: noop,
      returnedJsonData: noop,
      video: { getVideoRecs: noop, videoClicked: noop }
    }
  };
})();
