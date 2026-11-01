// Velor stand-in for the Google IMA HTML5 SDK v3 (ima3.js).
//
// Strategy: AdsLoader.requestAds() asynchronously dispatches
// ADS_MANAGER_LOADED with an AdsManager that holds no ads. Its start()
// dispatches CONTENT_PAUSE_REQUESTED on one tick and CONTENT_RESUME_REQUESTED
// followed by ALL_ADS_COMPLETED on the next: contrib-ads style players
// (video.js-ima, Brightcove) walk through a zero-length ad break instead of
// waiting out their preroll timeout, and hand-rolled players simply play
// content. AD_ERROR is never raised. destroy() cancels anything pending.
(function () {
  "use strict";
  const google = window.google = window.google || {};
  if (google.ima && google.ima.VERSION) return;
  const VERSION = "3.700.0";
  const freeze = Object.freeze;

  class Dispatcher {
    constructor() { this._listeners = []; this._timers = new Set(); this._destroyed = false; }
    addEventListener(type, listener, _useCapture, scope) {
      if (typeof listener === "function" || (listener && typeof listener.handleEvent === "function")) this._listeners.push({ type, listener, scope });
    }
    removeEventListener(type, listener) {
      this._listeners = this._listeners.filter((entry) => entry.type !== type || entry.listener !== listener);
    }
    dispatchEvent(event) {
      for (const entry of this._listeners.slice()) {
        if (entry.type !== event.type) continue;
        // A failing page listener must not stop the sequence.
        try {
          if (typeof entry.listener === "function") entry.listener.call(entry.scope || this, event);
          else entry.listener.handleEvent(event);
        } catch {}
      }
      return true;
    }
    _schedule(fn) {
      if (this._destroyed) return;
      const timer = setTimeout(() => { this._timers.delete(timer); if (!this._destroyed) fn(); }, 0);
      this._timers.add(timer);
    }
    destroy() {
      this._destroyed = true;
      for (const timer of this._timers) clearTimeout(timer);
      this._timers.clear();
      this._listeners = [];
    }
  }

  class AdError {
    constructor(type, code, message) { this._type = type; this._code = code; this._message = message || ""; }
    getErrorCode() { return this._code; }
    getInnerError() { return null; }
    getMessage() { return this._message; }
    getType() { return this._type; }
    getVastErrorCode() { return this._code; }
    toString() { return `AdError ${this._code}: ${this._message}`; }
  }
  AdError.Type = freeze({ AD_LOAD: "adLoadError", AD_PLAY: "adPlayError" });
  AdError.ErrorCode = freeze({
    ADS_REQUEST_NETWORK_ERROR: 1012, ASSET_FALLBACK_FAILED: 1021, AUTOPLAY_DISALLOWED: 1205, COMPANION_AD_LOADING_FAILED: 603,
    COMPANION_REQUIRED_ERROR: 602, CONSENT_MANAGEMENT_PROVIDER_NOT_READY: 1013, FAILED_TO_REQUEST_ADS: 1005,
    INVALID_ARGUMENTS: 1101, NONLINEAR_DIMENSIONS_ERROR: 501, OVERLAY_AD_LOADING_FAILED: 502, OVERLAY_AD_PLAYING_FAILED: 500,
    STREAM_INITIALIZATION_FAILED: 1020, UNKNOWN_AD_RESPONSE: 1010, UNKNOWN_ERROR: 900, UNSUPPORTED_LOCALE: 1011,
    VAST_ASSET_NOT_FOUND: 1007, VAST_EMPTY_RESPONSE: 1009, VAST_LINEAR_ASSET_MISMATCH: 403,
    VAST_LOAD_TIMEOUT: 301, VAST_MALFORMED_RESPONSE: 100, VAST_MEDIA_LOAD_TIMEOUT: 402, VAST_NO_ADS_AFTER_WRAPPER: 303,
    VAST_NONLINEAR_ASSET_MISMATCH: 503, VAST_PROBLEM_DISPLAYING_MEDIA_FILE: 405, VAST_SCHEMA_VALIDATION_ERROR: 101,
    VAST_TOO_MANY_REDIRECTS: 302, VAST_TRAFFICKING_ERROR: 200, VAST_UNEXPECTED_DURATION_ERROR: 202, VAST_UNEXPECTED_LINEARITY: 201,
    VAST_UNSUPPORTED_VERSION: 102, VAST_WRAPPER_ERROR: 300, VIDEO_ELEMENT_USED: 1201, VIDEO_ELEMENT_REQUIRED: 1202,
    VIDEO_PLAY_ERROR: 400, VPAID_ERROR: 901
  });

  class AdEvent {
    constructor(type) { this.type = type; }
    getAd() { return null; }
    getAdData() { return {}; }
  }
  AdEvent.Type = freeze({
    AD_BREAK_READY: "adBreakReady", AD_BREAK_ENDED: "adBreakEnded", AD_BREAK_FETCH_ERROR: "adBreakFetchError", AD_BREAK_STARTED: "adBreakStarted",
    AD_BUFFERING: "adBuffering", AD_CAN_PLAY: "adCanPlay", AD_METADATA: "adMetadata", AD_PERIOD_ENDED: "adPeriodEnded", AD_PERIOD_STARTED: "adPeriodStarted",
    AD_PROGRESS: "adProgress", ALL_ADS_COMPLETED: "allAdsCompleted", CLICK: "click", COMPLETE: "complete",
    CONTENT_PAUSE_REQUESTED: "contentPauseRequested", CONTENT_RESUME_REQUESTED: "contentResumeRequested", DURATION_CHANGE: "durationChange",
    EXPANDED_CHANGED: "expandedChanged", FIRST_QUARTILE: "firstQuartile", IMPRESSION: "impression", INTERACTION: "interaction",
    LINEAR_CHANGED: "linearChanged", LOADED: "loaded", LOG: "log", MIDPOINT: "midpoint", PAUSED: "pause", RESUMED: "resume",
    SKIPPABLE_STATE_CHANGED: "skippableStateChanged", SKIPPED: "skip", STARTED: "start", THIRD_QUARTILE: "thirdQuartile", USER_CLOSE: "userClose",
    VIDEO_CLICKED: "videoClicked", VIDEO_ICON_CLICKED: "videoIconClicked", VIEWABLE_IMPRESSION: "viewable_impression",
    VOLUME_CHANGED: "volumeChange", VOLUME_MUTED: "mute"
  });

  class AdErrorEvent {
    constructor(error, context) { this.type = AdErrorEvent.Type.AD_ERROR; this._error = error; this._context = context; }
    getError() { return this._error; }
    getUserRequestContext() { return this._context; }
  }
  AdErrorEvent.Type = freeze({ AD_ERROR: "adError" });

  class AdsManagerLoadedEvent {
    constructor(manager, context) { this.type = AdsManagerLoadedEvent.Type.ADS_MANAGER_LOADED; this._manager = manager; this._context = context; }
    getAdsManager() { return this._manager; }
    getUserRequestContext() { return this._context; }
  }
  AdsManagerLoadedEvent.Type = freeze({ ADS_MANAGER_LOADED: "adsManagerLoaded" });

  class AdsManager extends Dispatcher {
    constructor() { super(); this._volume = 1; }
    start() {
      this._schedule(() => {
        this.dispatchEvent(new AdEvent(AdEvent.Type.CONTENT_PAUSE_REQUESTED));
        this._schedule(() => {
          this.dispatchEvent(new AdEvent(AdEvent.Type.CONTENT_RESUME_REQUESTED));
          this.dispatchEvent(new AdEvent(AdEvent.Type.ALL_ADS_COMPLETED));
        });
      });
    }
    init() {}
    getCuePoints() { return []; }
    getRemainingTime() { return -1; }
    getVolume() { return this._volume; }
    setVolume(volume) { this._volume = volume; }
    getAdSkippableState() { return false; }
    getCurrentAd() { return null; }
    isCustomClickTrackingUsed() { return false; }
    isCustomPlaybackUsed() { return false; }
    collapse() {}
    configureAdsManager() {}
    discardAdBreak() {}
    expand() {}
    focus() {}
    pause() {}
    requestNextAdBreak() {}
    resize() {}
    resume() {}
    skip() {}
    stop() {}
    updateAdsRenderingSettings() {}
  }

  class ImaSdkSettings {
    constructor() {
      this._ = {
        AutoPlayAdBreaks: true, CompanionBackfill: "always", CookiesEnabled: true, DisableCustomPlaybackForIOS10Plus: false, FeatureFlags: {},
        IsVpaidAdapter: false, Locale: "en", NumRedirects: 4, PlayerType: "", PlayerVersion: "", Ppid: "", SessionId: "", VpaidAllowed: true, VpaidMode: 1
      };
    }
  }
  for (const key of Object.keys(new ImaSdkSettings()._)) {
    ImaSdkSettings.prototype[`set${key}`] = function (value) { this._[key] = value; };
    ImaSdkSettings.prototype[`get${key}`] = function () { return this._[key]; };
  }
  ImaSdkSettings.prototype.isCookiesEnabled = ImaSdkSettings.prototype.getCookiesEnabled;
  ImaSdkSettings.prototype.isVpaidAdapter = ImaSdkSettings.prototype.getIsVpaidAdapter;
  ImaSdkSettings.VpaidMode = freeze({ DISABLED: 0, ENABLED: 1, INSECURE: 2 });
  ImaSdkSettings.CompanionBackfillMode = freeze({ ALWAYS: "always", ON_MASTER_AD: "on_master_ad" });

  class AdsLoader extends Dispatcher {
    constructor(container) { super(); this._container = container; this._settings = new ImaSdkSettings(); }
    contentComplete() {}
    getSettings() { return this._settings; }
    getVersion() { return VERSION; }
    requestAds(request, context) {
      this._schedule(() => this.dispatchEvent(new AdsManagerLoadedEvent(new AdsManager(), context)));
    }
  }

  class AdDisplayContainer {
    constructor(container, video, clickTracking) { this._container = container; this._video = video; this._clickTracking = clickTracking; }
    initialize() {}
    destroy() {}
  }
  class AdsRequest {
    setAdWillAutoPlay() {}
    setAdWillPlayMuted() {}
    setContinuousPlayback() {}
  }
  class AdsRenderingSettings {
    constructor() {
      Object.assign(this, {
        autoAlign: true, bitrate: -1, enablePreloading: false, loadVideoTimeout: -1, mimeTypes: [], playAdsAfterTime: -1,
        restoreCustomPlaybackStateOnAdBreakComplete: false, uiElements: [], useStyledLinearAds: false, useStyledNonLinearAds: false
      });
    }
  }
  AdsRenderingSettings.AUTO_SCALE = -1;
  class CompanionAdSelectionSettings {
    constructor() { Object.assign(this, { adSlotIds: [], creativeType: "All", nearMatchPercent: 90, resourceType: "All", sizeCriteria: "SelectExactMatch" }); }
  }
  CompanionAdSelectionSettings.CreativeType = freeze({ ALL: "All", FLASH: "Flash", IMAGE: "Image" });
  CompanionAdSelectionSettings.ResourceType = freeze({ ALL: "All", HTML: "Html", IFRAME: "IFrame", STATIC: "Static" });
  CompanionAdSelectionSettings.SizeCriteria = freeze({ IGNORE: "IgnoreSize", SELECT_EXACT_MATCH: "SelectExactMatch", SELECT_NEAR_MATCH: "SelectNearMatch" });

  google.ima = {
    VERSION,
    AdDisplayContainer, AdError, AdErrorEvent, AdEvent, AdsLoader, AdsManagerLoadedEvent, AdsRenderingSettings, AdsRequest,
    CompanionAdSelectionSettings, ImaSdkSettings,
    OmidAccessMode: freeze({ DOMAIN: "domain", FULL: "full", LIMITED: "limited" }),
    OmidVerificationVendor: freeze({ OTHER: 1, MOAT: 2, DOUBLEVERIFY: 3, INTEGRAL_AD_SCIENCE: 4, PIXELATE: 5, NIELSEN: 6, COMSCORE: 7, MEETRICS: 8, GOOGLE: 9 }),
    UiElements: freeze({ AD_ATTRIBUTION: "adAttribution", COUNTDOWN: "countdown" }),
    ViewMode: freeze({ FULLSCREEN: "fullscreen", NORMAL: "normal" }),
    settings: new ImaSdkSettings()
  };
})();
