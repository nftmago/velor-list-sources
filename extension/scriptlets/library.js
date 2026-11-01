// Velor's scriptlet library: the page-script defusers that filter lists
// request with `example.com##+js(name, …)` (uBlock Origin) or
// `example.com#%#//scriptlet('name', …)` (AdGuard). Written from the
// documented behaviour of those scriptlets; not derived from their sources.
//
// Contract with the compiler: for one scriptlet it emits the `toString()`
// of every function in `helpers` followed by `fn`'s, inside a single IIFE,
// then calls `fn(...args)` once per argument list, every argument a string
// (omitted arguments arrive as ""). So every function here is a named
// `function` declaration that touches only its parameters, browser globals
// and the helpers its entry lists; nothing closes over module scope, and
// the emitted file may be strict or sloppy. Helpers are flat: an entry's
// `helpers` list is the full transitive set, in dependency order.
//
// Every scriptlet swallows its own errors; the only deliberate throws are
// the abort-* accessors, which fire inside the page's accessing script.

// ---------------------------------------------------------------- helpers

// Turns a filter needle into a predicate over strings: "" matches anything,
// "/re/flags" is a regular expression (only real flags count, so a path like
// "/api/graphql" stays literal; g and y are dropped so test() stays
// stateless), anything else is a literal substring. With `negatable`, a
// leading "!" inverts the result. Returns null for an invalid regular
// expression so the caller does nothing rather than guess.
function velorMatcher(needle, negatable) {
  let text = needle == null ? "" : String(needle);
  let negate = false;
  if (negatable && text.startsWith("!")) {
    negate = true;
    text = text.slice(1);
  }
  const regex = /^\/(.+)\/([dgimsuvy]*)$/s.exec(text);
  let test;
  if (regex) {
    try {
      const pattern = new RegExp(regex[1], regex[2].replace(/[gy]/g, ""));
      test = (value) => pattern.test(value);
    } catch (_) {
      return null;
    }
  } else {
    test = (value) => value.includes(text);
  }
  return (value) => {
    let hit = false;
    try { hit = test(String(value)); } catch (_) { return false; }
    return negate ? !hit : hit;
  };
}

// Walks a dotted property chain from `root` and calls `define(owner, key,
// descriptor)` for the last link, where `descriptor` is the existing own or
// inherited descriptor (if any). Missing intermediate objects are trapped
// with an accessor so the leaf is defined as soon as the page creates them;
// an existing trap on the same link is chained, not replaced. Nothing is
// redefined when it is non-configurable or an inherited accessor (so
// `document.body.x` never shadows `body`), and a primitive link ends the
// walk.
function velorOnChain(root, chain, define) {
  const parts = String(chain).split(".");
  const walk = (owner, index) => {
    const key = parts[index];
    const own = Object.getOwnPropertyDescriptor(owner, key);
    if (index === parts.length - 1) {
      if (own && own.configurable === false) return;
      let descriptor = own;
      for (let proto = Object.getPrototypeOf(owner); !descriptor && proto; proto = Object.getPrototypeOf(proto)) {
        descriptor = Object.getOwnPropertyDescriptor(proto, key);
      }
      define(owner, key, descriptor);
      return;
    }
    let value = owner[key];
    if (value !== undefined && value !== null) {
      if (typeof value === "object" || typeof value === "function") walk(value, index + 1);
      return;
    }
    if (own ? own.configurable === false : key in owner) return;
    const previous = own && (own.get || own.set) ? own : null;
    Object.defineProperty(owner, key, {
      configurable: true,
      enumerable: Boolean(own && own.enumerable),
      get() { return previous ? (previous.get ? previous.get.call(this) : undefined) : value; },
      set(next) {
        if (previous) {
          if (previous.set) previous.set.call(this, next);
        } else {
          value = next;
        }
        if (next !== null && (typeof next === "object" || typeof next === "function")) walk(next, index + 1);
      }
    });
  };
  walk(root, 0);
}

// Traps `chain` so every read or write first runs `check`, which throws to
// abort the accessing script; otherwise the property behaves as before.
function velorGuardChain(chain, check) {
  velorOnChain(globalThis, chain, (owner, key, descriptor) => {
    const accessor = Boolean(descriptor && (descriptor.get || descriptor.set));
    let value = descriptor && !accessor ? descriptor.value : undefined;
    Object.defineProperty(owner, key, {
      configurable: true,
      enumerable: Boolean(descriptor && descriptor.enumerable),
      get() {
        check();
        return accessor ? (descriptor.get ? descriptor.get.call(this) : undefined) : value;
      },
      set(next) {
        check();
        if (accessor) {
          if (descriptor.set) descriptor.set.call(this, next);
        } else {
          value = next;
        }
      }
    });
  });
}

// The error an aborted script sees: a ReferenceError with an unguessable
// message, so anti-adblock code cannot special-case it.
function velorAbortError() {
  return new ReferenceError(Math.random().toString(36).slice(2));
}

// Builds a predicate over the current call stack for abort-on-stack-trace
// style needles: "inlineScript" (a frame from the page's own URL),
// "injectedScript" (an anonymous frame), or a literal/regex, optionally "!"
// negated, matched against "stackDepth:N" followed by the frames joined by
// tabs, as uBO formats it. Frames from this script are dropped first, and
// V8's ten-frame default is lifted while capturing so deeper callers count.
function velorStackMatcher(needle) {
  const text = needle == null ? "" : String(needle);
  const special = text === "inlineScript" || text === "injectedScript";
  const matches = special ? null : velorMatcher(text, true);
  if (!special && !matches) return null;
  const pageUrl = String((globalThis.location && globalThis.location.href) || "").split("#")[0];
  const ownLine = String(new Error().stack || "").split("\n")[1] || "";
  const ownUrl = ownLine.replace(/^\s*at\s+/, "").replace(/^.*\(/, "").replace(/\)$/, "").replace(/:\d+:\d+$/, "");
  const capture = () => {
    const limit = Error.stackTraceLimit;
    try { Error.stackTraceLimit = 64; } catch (_) { /* keep the default depth */ }
    const stack = String(new Error().stack || "");
    try { Error.stackTraceLimit = limit; } catch (_) { /* nothing to restore */ }
    return stack;
  };
  return () => {
    let frames = capture().split("\n").slice(1).map((line) => line.trim());
    if (ownUrl) frames = frames.filter((frame) => !frame.includes(ownUrl));
    if (text === "inlineScript") return Boolean(pageUrl) && frames.some((frame) => frame.includes(pageUrl + ":"));
    if (text === "injectedScript") return frames.some((frame) => frame.includes("<anonymous>"));
    return matches(`stackDepth:${frames.length}\t${frames.join("\t")}`);
  };
}

// Makes `wrapper` pass for `native` to code that inspects functions: same
// name and length, and Function.prototype.toString reports the native
// source. Each call layers one lookup onto toString, so several scriptlets
// on one page compose and toString itself keeps looking native.
function velorMaskNative(wrapper, native) {
  const masked = new Map([[wrapper, native]]);
  const previous = Function.prototype.toString;
  const replacement = function toString() {
    return previous.call(masked.has(this) ? masked.get(this) : this);
  };
  masked.set(replacement, previous);
  try {
    Object.defineProperty(Function.prototype, "toString", { value: replacement, writable: true, configurable: true });
    Object.defineProperty(wrapper, "name", { value: native.name, configurable: true });
    Object.defineProperty(wrapper, "length", { value: native.length, configurable: true });
  } catch (_) { /* leave the wrapper recognisable rather than fail */ }
  return wrapper;
}

// Parses uBO/AdGuard request conditions ("doubleclick method:POST
// body:/re/") into a predicate over a request's properties. Every condition
// must hold; "" and "*" match everything; an invalid regex yields null.
function velorRequestMatcher(propsToMatch) {
  const text = String(propsToMatch == null ? "" : propsToMatch).trim();
  if (text === "" || text === "*") return () => true;
  const keys = ["url", "method", "mode", "credentials", "cache", "redirect", "referrer", "referrerPolicy", "integrity",
    "keepalive", "body", "type", "async", "responseType", "withCredentials"];
  const conditions = [];
  for (const token of text.split(/\s+/)) {
    const pair = /^(!?)([a-zA-Z]+):([^]*)$/.exec(token);
    const key = pair && keys.includes(pair[2]) ? pair[2] : "url";
    const matches = velorMatcher(key === "url" ? token : pair[1] + pair[3], true);
    if (!matches) return null;
    conditions.push((props) => matches(props[key] === undefined ? "" : props[key]));
  }
  return (props) => conditions.every((condition) => condition(props));
}

// Body text for a defused request: emptyObj → "{}", emptyArr → "[]",
// emptyStr → "", true → ten random characters, length:N[-M] → filler of
// that size (capped at 500,000), anything else → `fallback`.
function velorResponseBody(directive, fallback) {
  const text = String(directive == null ? "" : directive).trim();
  if (text === "emptyObj") return "{}";
  if (text === "emptyArr") return "[]";
  if (text === "emptyStr") return "";
  if (text === "true") return Math.random().toString(36).slice(2, 12).padEnd(10, "0");
  const range = /^length:(\d+)(?:-(\d+))?$/.exec(text);
  if (range) {
    const min = Number(range[1]);
    const max = Number(range[2] || range[1]);
    return "0".repeat(Math.min(500000, Math.floor(min + Math.random() * Math.max(0, max - min + 1))));
  }
  return fallback;
}

// Walks a json-prune path ("a.b", "list.[].ad", "*.src", "*") from `root`,
// deleting every matching leaf when `remove` is set (array leaves are
// spliced out). Returns whether any leaf was found. "*" visits every own
// key, "[]" every array element; "[-]" and "{-}" instead drop the array
// element or object entry under which the rest of the path exists; a
// trailing ".[=].value" only counts leaves equal to value (true, false, an
// integer, a /regex/ tested on strings, or the literal text). JSONPath
// ("$..") is not supported: "$" is just a key, so such paths match nothing.
function velorPrunePath(root, path, remove) {
  let text = String(path);
  let matchesValue = null;
  const marker = text.indexOf(".[=].");
  if (marker !== -1) {
    const raw = text.slice(marker + 5);
    text = text.slice(0, marker);
    const regex = /^\/(.+)\/([dgimsuvy]*)$/s.exec(raw);
    if (regex) {
      let pattern;
      try { pattern = new RegExp(regex[1], regex[2].replace(/[gy]/g, "")); } catch (_) { return false; }
      matchesValue = (value) => typeof value === "string" && pattern.test(value);
    } else {
      const expected = raw === "true" ? true : raw === "false" ? false : /^\d+$/.test(raw) ? Number(raw) : raw;
      matchesValue = (value) => value === expected;
    }
  }
  const parts = text.replace(/\[\]/g, ".[].").split(".").filter(Boolean);
  if (parts.length === 0) return false;
  const walk = (node, index, prune) => {
    if (node === null || typeof node !== "object") return false;
    const part = parts[index];
    const last = index === parts.length - 1;
    let found = false;
    if (!last && (part === "[-]" || part === "{-}")) {
      if ((part === "[-]") !== Array.isArray(node)) return false;
      for (const key of Object.keys(node).reverse()) {
        if (!walk(node[key], index + 1, false)) continue;
        found = true;
        if (!prune) continue;
        if (Array.isArray(node)) node.splice(Number(key), 1);
        else delete node[key];
      }
      return found;
    }
    let keys;
    if (part === "*") keys = Object.keys(node);
    else if (part === "[]") keys = Array.isArray(node) ? Object.keys(node) : [];
    else keys = Object.prototype.hasOwnProperty.call(node, part) ? [part] : [];
    for (const key of keys.reverse()) {
      if (!last) {
        if (walk(node[key], index + 1, prune)) found = true;
        continue;
      }
      if (matchesValue && !matchesValue(node[key])) continue;
      found = true;
      if (!prune) continue;
      if (Array.isArray(node) && /^\d+$/.test(key)) node.splice(Number(key), 1);
      else delete node[key];
    }
    return found;
  };
  return walk(root, 0, Boolean(remove));
}

// Runs `apply` now and after each batch of DOM mutations (observer callbacks
// are already coalesced per task, which is throttle enough). Unless
// `behavior` contains "stay" it disconnects a second after the load event;
// "complete" waits for load before starting at all.
function velorWatchDom(apply, behavior, options) {
  const flags = String(behavior == null ? "" : behavior).split(/\s+/);
  const run = () => { try { apply(); } catch (_) { /* keep observing */ } };
  const start = () => {
    run();
    const observer = new MutationObserver(run);
    observer.observe(document.documentElement || document, options);
    if (flags.includes("stay")) return;
    const stop = () => {
      run();
      globalThis.setTimeout(() => observer.disconnect(), 1000);
    };
    if (document.readyState === "complete") stop();
    else globalThis.addEventListener("load", stop, { once: true });
  };
  if (flags.includes("complete") && document.readyState !== "complete") globalThis.addEventListener("load", start, { once: true });
  else start();
}

// Shared by no-setTimeout-if and no-setInterval-if: calls whose stringified
// callback matches `needle` and whose delay matches `delay` ("1000",
// "500-1500", "-500", "1000-", each optionally "!" negated; "" is any) run a
// no-op instead, so the page still gets a timer id it can clear.
function velorDefuseTimer(method, needle, delay) {
  const matchesCallback = velorMatcher(needle, true);
  const native = globalThis[method];
  if (!matchesCallback || typeof native !== "function") return;
  let text = String(delay == null ? "" : delay).trim();
  const negate = text.startsWith("!");
  if (negate) text = text.slice(1);
  const range = /^(\d*)(-?)(\d*)$/.exec(text);
  if (!range || (text !== "" && range[1] === "" && range[3] === "")) return;
  const min = range[1] === "" ? 0 : Number(range[1]);
  const max = range[2] === "" ? min : range[3] === "" ? Infinity : Number(range[3]);
  const matchesDelay = (value) => {
    if (text === "") return true;
    const actual = Math.max(0, Math.floor(Number(value)) || 0);
    const hit = actual >= min && actual <= max;
    return negate ? !hit : hit;
  };
  globalThis[method] = velorMaskNative(function (callback, timeout) {
    let defuse = false;
    try {
      defuse = matchesCallback(typeof callback === "function" ? String(callback) : callback) && matchesDelay(timeout);
    } catch (_) { /* treat as no match */ }
    if (defuse) arguments[0] = function () {};
    return native.apply(this, arguments);
  }, native);
}

// Shared by adjust-setTimeout and adjust-setInterval: callbacks matching
// `needle` whose delay equals `delay` (default 1000, "*" for any) run with
// the delay multiplied by `boost` (default 0.05, clamped to 0.001–50).
function velorAdjustTimer(method, needle, delay, boost) {
  const matches = velorMatcher(needle, false);
  const native = globalThis[method];
  if (!matches || typeof native !== "function") return;
  const delayText = String(delay == null ? "" : delay).trim();
  const target = delayText === "" ? 1000 : delayText === "*" ? null : Number(delayText);
  if (target !== null && !Number.isFinite(target)) return;
  let factor = Number(String(boost == null ? "" : boost).trim());
  if (!Number.isFinite(factor) || factor <= 0) factor = 0.05;
  factor = Math.min(50, Math.max(0.001, factor));
  globalThis[method] = velorMaskNative(function (callback, timeout) {
    try {
      const actual = Math.max(0, Number(timeout) || 0);
      if ((target === null || actual === target) && matches(typeof callback === "function" ? String(callback) : callback)) {
        arguments[1] = actual * factor;
      }
    } catch (_) { /* leave the call alone */ }
    return native.apply(this, arguments);
  }, native);
}

// Shared by the storage scriptlets. Only the documented safe values are
// written unless `trusted`, which takes any text with the time keywords
// expanded; "$remove$" deletes the key, which may then be a /regex/ (a regex
// key with any other value is refused).
function velorSetStorageItem(storage, key, value, trusted) {
  const name = String(key == null ? "" : key).trim();
  const text = String(value == null ? "" : value).trim();
  const isRegex = /^\/(.+)\/([a-z]*)$/.test(name);
  if (!storage || !name) return;
  if (text === "$remove$") {
    const matches = isRegex ? velorMatcher(name, false) : (candidate) => candidate === name;
    if (!matches) return;
    const keys = [];
    for (let i = 0; i < storage.length; i += 1) keys.push(storage.key(i));
    for (const candidate of keys) if (candidate !== null && matches(candidate)) storage.removeItem(candidate);
    return;
  }
  if (isRegex) return;
  if (trusted) {
    const mapped = { emptyArr: "[]", emptyObj: "{}" };
    storage.setItem(name, velorTimeKeywords(Object.prototype.hasOwnProperty.call(mapped, text) ? mapped[text] : text));
    return;
  }
  const words = ["undefined", "null", "false", "true", "yes", "no", "on", "off", "accept", "accepted", "reject", "rejected",
    "allow", "allowed", "deny", "denied", "forbidden", "forever", "ok", "necessary", "required", "hide", "hidden",
    "essential", "nonessential", "checked", "dismiss", "dismissed", "enable", "enabled", "disable", "disabled"];
  const mapped = { "''": "", "\"\"": "", "": "", emptyarr: "[]", emptyobj: "{}", "[]": "[]", "{}": "{}" };
  let result;
  if (words.includes(text.toLowerCase())) result = text;
  else if (Object.prototype.hasOwnProperty.call(mapped, text.toLowerCase())) result = mapped[text.toLowerCase()];
  else if (/^-?\d+$/.test(text) && Math.abs(Number(text)) <= 32767) result = text;
  else return;
  storage.setItem(name, result);
}

// Shared by noeval-if and noeval: evaluating code that matches `needle`
// ("" is any) returns undefined; other code goes to the native eval
// (indirectly, as uBO's does).
function velorDefuseEval(needle) {
  const matches = velorMatcher(needle, false);
  const native = globalThis.eval;
  if (!matches || typeof native !== "function") return;
  globalThis.eval = velorMaskNative(function (code) {
    if (typeof code === "string" && matches(code)) return undefined;
    return native(code);
  }, native);
}

// Shared by set-constant and trusted-set-constant. Defines `chain` as a
// constant; `rest` is uBO's positional [stack, valueWrapper] or its keyword
// form ("as", wrapper | "stack", needle). Untrusted values come from the
// documented keyword table (booleans, stub functions, integers within
// ±32767…); trusted ones may also be JSON — a "json:" prefix, a bare JSON
// literal as AdGuard writes it, or uBO's {"value": …} envelope. Like uBO, an
// untrusted constant is not applied over an existing value of a different
// type and a later page write of a different type is accepted (the property
// then behaves normally); a trusted constant overrides any value and
// swallows writes.
function velorSetConstant(trusted, chain, value, rest) {
  const text = String(value == null ? "" : value).trim();
  let constant;
  switch (text) {
    case "undefined": constant = undefined; break;
    case "null": constant = null; break;
    case "true": constant = true; break;
    case "false": constant = false; break;
    case "''": case "\"\"": case "": constant = ""; break;
    case "yes": case "no": constant = text; break;
    case "noopFunc": constant = function () {}; break;
    case "trueFunc": constant = function () { return true; }; break;
    case "falseFunc": constant = function () { return false; }; break;
    case "throwFunc": constant = function () { throw new Error(); }; break;
    case "noopCallbackFunc": constant = function () { return function () {}; }; break;
    case "noopPromiseResolve": constant = function () { return Promise.resolve(typeof Response === "function" ? new Response("") : undefined); }; break;
    case "noopPromiseReject": constant = function () { return Promise.reject(); }; break;
    case "emptyArr": case "[]": constant = []; break;
    case "emptyObj": case "{}": constant = {}; break;
    default:
      if (/^-?\d+$/.test(text)) {
        if (Math.abs(Number(text)) > 32767) return;
        constant = Number(text);
        break;
      }
      if (!trusted) return;
      try { constant = JSON.parse(text.startsWith("json:") ? text.slice(5) : text); } catch (_) { return; }
      if (!text.startsWith("json:") && constant !== null && typeof constant === "object" && Object.keys(constant).join() === "value") constant = constant.value;
  }
  let stack = "";
  let wrapper = "";
  if (["as", "stack", "runAt"].includes(rest[0]) || ["as", "stack", "runAt"].includes(rest[2])) {
    for (let i = 0; i + 1 < rest.length; i += 2) {
      if (rest[i] === "as") wrapper = rest[i + 1];
      else if (rest[i] === "stack") stack = rest[i + 1];
    }
  } else {
    stack = rest[0] || "";
    wrapper = rest[1] || "";
  }
  const inner = constant;
  switch (String(wrapper).replace(/^as/, "").toLowerCase()) {
    case "function": constant = function () { return inner; }; break;
    case "callback": constant = function () { return function () { return inner; }; }; break;
    case "resolved": constant = Promise.resolve(inner); break;
    case "rejected": constant = Promise.reject(inner); constant.catch(() => {}); break;
    default: break;
  }
  const onStack = stack ? velorStackMatcher(stack) : null;
  const differs = (a, b) => !trusted && a !== undefined && a !== null && b !== undefined && b !== null && typeof a !== typeof b;
  velorOnChain(globalThis, chain, (owner, key, descriptor) => {
    let actual;
    try {
      actual = descriptor ? (descriptor.get ? descriptor.get.call(owner) : descriptor.value) : undefined;
    } catch (_) { actual = undefined; }
    if (differs(actual, constant)) return;
    let abandoned = false;
    Object.defineProperty(owner, key, {
      configurable: true,
      enumerable: Boolean(descriptor && descriptor.enumerable),
      get() { return abandoned || (onStack && !onStack()) ? actual : constant; },
      set(next) {
        if (trusted) return;
        if (differs(next, constant)) abandoned = true;
        actual = next;
      }
    });
  });
}

// Resolves a dotted method path from globalThis and replaces the method with
// a native-looking wrapper that runs `handler(native, thisArg, args)`. When
// the method really lives further up the prototype chain (localStorage's
// getItem is Storage.prototype's, and Storage objects cannot carry own
// properties; HTMLScriptElement.prototype's setAttribute is Element's) the
// replacement goes there, but only calls on the named object, or on
// something inheriting from it, are handled; the rest pass straight
// through. Returns whether anything was wrapped.
function velorWrapMethod(path, handler) {
  const parts = String(path).split(".");
  let owner = globalThis;
  for (const part of parts.slice(0, -1)) {
    owner = owner[part];
    if (owner === null || (typeof owner !== "object" && typeof owner !== "function")) return false;
  }
  const key = parts[parts.length - 1];
  let holder = owner;
  while (holder && !Object.prototype.hasOwnProperty.call(holder, key)) holder = Object.getPrototypeOf(holder);
  const descriptor = holder && Object.getOwnPropertyDescriptor(holder, key);
  if (!descriptor || typeof descriptor.value !== "function") return false;
  if (descriptor.configurable === false && descriptor.writable === false) return false;
  const native = descriptor.value;
  const scoped = holder !== owner;
  const named = (receiver) => receiver === owner || Object.prototype.isPrototypeOf.call(owner, receiver);
  Object.defineProperty(holder, key, { ...descriptor, value: velorMaskNative(function () {
    if (scoped && !named(this)) return native.apply(this, arguments);
    return handler(native, this, arguments);
  }, native) });
  return true;
}

// The properties of a fetch call, defaulted as the browser would, for
// matching request conditions against: the URL plus the Request or init
// fields.
function velorFetchProps(input, init) {
  const request = input !== null && typeof input === "object" && typeof input.url === "string" ? input : null;
  const props = { url: request ? request.url : String(input), method: "GET", mode: "cors", credentials: "same-origin", cache: "default",
    redirect: "follow", referrer: "about:client", referrerPolicy: "", integrity: "", keepalive: false, body: "" };
  for (const key of Object.keys(props)) {
    if (request && key !== "url" && key !== "body" && request[key] !== undefined) props[key] = request[key];
    if (init && init[key] !== undefined) props[key] = init[key];
  }
  return props;
}

// Shared by the response-pruning scriptlets: a fetch whose request
// properties satisfy `matches` resolves through `rewrite(response)`, which
// returns the response to hand back (or a promise of it); a rewrite that
// fails or returns nothing leaves the original. Other fetches, and fetches
// that fail, are untouched.
function velorRewriteFetch(matches, rewrite) {
  const native = globalThis.fetch;
  if (typeof native !== "function") return;
  globalThis.fetch = velorMaskNative(function (input, init) {
    const result = native.apply(this, arguments);
    let hit = false;
    try { hit = matches(velorFetchProps(input, init)); } catch (_) { hit = false; }
    if (!hit) return result;
    return Promise.resolve(result).then((response) => Promise.resolve(response).then(rewrite).then((next) => next || response, () => response));
  }, native);
}

// A copy of `response` carrying `body` instead, with the same status,
// headers, type, url and flags, so the page cannot tell it was rewritten.
function velorReplaceResponseBody(response, body) {
  const replacement = new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
  for (const key of ["ok", "redirected", "type", "url"]) {
    try { Object.defineProperty(replacement, key, { value: response[key], configurable: true }); } catch (_) { /* a plain response is still a response */ }
  }
  return replacement;
}

// Shared by the response-pruning scriptlets: requests whose method and URL
// satisfy `matches` have their response, responseText and responseXML
// passed through `rewrite(value)` on every read (cached per value, so
// repeated reads are cheap); a rewrite that throws yields the original.
function velorRewriteXhr(matches, rewrite) {
  const proto = globalThis.XMLHttpRequest && globalThis.XMLHttpRequest.prototype;
  if (!proto || typeof proto.open !== "function") return;
  const pending = new WeakMap();
  const open = proto.open;
  proto.open = velorMaskNative(function (method, url) {
    let hit = false;
    try { hit = matches({ method: String(method), url: String(url) }); } catch (_) { hit = false; }
    if (hit) pending.set(this, new Map());
    else pending.delete(this);
    return open.apply(this, arguments);
  }, open);
  for (const key of ["response", "responseText", "responseXML"]) {
    const descriptor = Object.getOwnPropertyDescriptor(proto, key);
    if (!descriptor || !descriptor.get || !descriptor.configurable) continue;
    Object.defineProperty(proto, key, { ...descriptor, get() {
      const value = descriptor.get.call(this);
      const cache = pending.get(this);
      if (!cache) return value;
      const previous = cache.get(key);
      if (previous && previous.input === value) return previous.output;
      let output = value;
      try { output = rewrite(value); } catch (_) { output = value; }
      cache.set(key, { input: value, output });
      return output;
    } });
  }
}

// The values set-cookie and set-cookie-reload may write: consent and
// dismissal words (case preserved), emptyArr, emptyObj, integers within
// ±32767. Anything else yields null.
function velorSafeCookieValue(value) {
  const text = String(value == null ? "" : value).trim();
  const words = ["true", "t", "false", "f", "yes", "y", "no", "n", "ok", "on", "off", "all", "none", "accept", "accepted",
    "notaccepted", "reject", "rejected", "allow", "allowed", "disallow", "deny", "denied", "decline", "declined", "approved",
    "disapproved", "enable", "enabled", "disable", "disabled", "mandatory", "necessary", "required", "hide", "hidden",
    "essential", "nonessential", "checked", "unchecked", "forbidden", "forever", "dismiss", "dismissed", "functional",
    "granted", "done", "closed", "next", "agree", "disagree"];
  if (words.includes(text.toLowerCase())) return text;
  if (text === "emptyArr") return "[]";
  if (text === "emptyObj") return "{}";
  if (/^-?\d+$/.test(text) && Math.abs(Number(text)) <= 32767) return text;
  return null;
}

// Shared by the cookie scriptlets: writes `name=value` for path "/" (the
// default) or no path ("none"), with the optional expires and domain
// attributes. A value with characters a cookie cannot carry is
// percent-encoded; a name or domain that could smuggle attributes is
// refused. With `reload`, the page reloads once the cookie reads back as
// written — unless it already did, so a jar that refuses the cookie never
// loops.
function velorSetCookie(name, value, options) {
  const key = String(name == null ? "" : name).trim();
  let text = String(value == null ? "" : value);
  const { path, expires, domain, reload } = options || {};
  if (!key || /[;=,\s]/.test(key)) return;
  if (domain && !/^\.?[\w.-]+$/.test(domain)) return;
  if (/[^ -:<-[\]-~]/.test(text)) text = encodeURIComponent(text);
  const read = () => {
    for (const entry of String(document.cookie).split(";")) {
      const pair = entry.trim();
      if (pair.startsWith(`${key}=`)) return pair.slice(key.length + 1);
    }
    return undefined;
  };
  if (reload && read() === text) return;
  let cookie = `${key}=${text}`;
  if (expires) cookie += `; expires=${expires}`;
  if (String(path == null ? "" : path).trim() !== "none") cookie += "; path=/";
  if (domain) cookie += `; domain=${domain}`;
  document.cookie = cookie;
  if (reload && read() === text) globalThis.location.reload();
}

// Expands the trusted-* time keywords in `text`: $now$ (milliseconds since
// the epoch), $currentDate$ (Date() text) and $currentISODate$ (ISO 8601),
// all taken from `now` (default: this moment).
function velorTimeKeywords(text, now) {
  const time = now || new Date();
  return String(text).replaceAll("$now$", String(time.getTime())).replaceAll("$currentDate$", time.toString())
    .replaceAll("$currentISODate$", time.toISOString());
}

// Shared by trusted-set-cookie and trusted-set-cookie-reload: any value,
// with the time keywords expanded; `offset` is "" (a session cookie),
// "1day", "1year" or a number of seconds from now; `rest` is uBO's keyword
// pairs ("domain", host — a /regex/ is matched against the hostname —
// | "reload", 1) or AdGuard's positional domain.
function velorTrustedSetCookie(name, value, offset, path, rest, reload) {
  const time = new Date();
  const text = velorTimeKeywords(value == null ? "" : value, time);
  const span = String(offset == null ? "" : offset).trim();
  if (span === "1day") time.setDate(time.getDate() + 1);
  else if (span === "1year") time.setFullYear(time.getFullYear() + 1);
  else if (/^\d+$/.test(span)) time.setSeconds(time.getSeconds() + Number(span));
  else if (span !== "") return;
  const extra = rest.length === 1 ? ["domain", rest[0]] : rest;
  let domain = "";
  for (let i = 0; i + 1 < extra.length; i += 2) {
    if (extra[i] === "domain") domain = String(extra[i + 1]).trim();
    else if (extra[i] === "reload") reload = true;
  }
  const regex = /^\/(.+)\/$/.exec(domain);
  if (regex) {
    const match = new RegExp(regex[1]).exec(String((globalThis.location && globalThis.location.hostname) || ""));
    domain = match ? match[0] : "";
  }
  velorSetCookie(name, text, { path, expires: span === "" ? "" : time.toUTCString(), domain, reload });
}

// Shared by json-prune-fetch-response and json-prune-xhr-response: their
// trailing arguments are uBO's keyword pairs ("propsToMatch", conditions |
// "stackToMatch", needle) or AdGuard's positional [conditions, stack].
function velorPruneOptions(rest) {
  const options = { propsToMatch: "", stack: "" };
  const keywords = ["propsToMatch", "stackToMatch"];
  if (keywords.includes(rest[0]) || keywords.includes(rest[2])) {
    for (let i = 0; i + 1 < rest.length; i += 2) {
      if (rest[i] === "propsToMatch") options.propsToMatch = rest[i + 1];
      else if (rest[i] === "stackToMatch") options.stack = rest[i + 1];
    }
  } else {
    options.propsToMatch = rest[0] || "";
    options.stack = rest[1] || "";
  }
  return options;
}

// Shared by hide-in-shadow-dom and remove-in-shadow-dom: calls `act` on
// every element matching `selector` found through the open shadow roots
// under `baseSelector` (default: the whole page) — in each root, its nested
// roots and the hosts' own subtrees — now and, once per frame, as the page
// or any root seen so far changes.
function velorInShadowDom(selector, baseSelector, act) {
  const query = String(selector == null ? "" : selector).trim();
  const base = String(baseSelector == null ? "" : baseSelector).trim();
  if (!query) return;
  const observed = new WeakSet();
  let scheduled = false;
  const observer = new MutationObserver(() => {
    if (scheduled) return;
    scheduled = true;
    globalThis.requestAnimationFrame(() => { scheduled = false; run(); });
  });
  const watch = (root) => {
    if (!root || observed.has(root)) return;
    observed.add(root);
    observer.observe(root, { childList: true, subtree: true });
  };
  const sweep = () => {
    const hosts = [];
    const consider = (element) => { if (element && element.shadowRoot) hosts.push(element); };
    for (const scope of base ? document.querySelectorAll(base) : [document.documentElement]) {
      consider(scope);
      if (scope) for (const element of scope.querySelectorAll("*")) consider(element);
    }
    const seen = new Set();
    while (hosts.length) {
      const host = hosts.pop();
      const root = host.shadowRoot;
      if (seen.has(root)) continue;
      seen.add(root);
      watch(root);
      for (const element of [...host.querySelectorAll(query), ...root.querySelectorAll(query)]) {
        try { act(element); } catch (_) { /* on to the next element */ }
      }
      for (const element of root.querySelectorAll("*")) consider(element);
    }
  };
  const run = () => { try { sweep(); } catch (_) { /* keep observing */ } };
  run();
  watch(document.documentElement || document);
}

// ------------------------------------------------------------- scriptlets

// set-constant(chain, value, [stack, valueWrapper] | [as, function|callback|resolved|rejected])
function setConstant(chain, value, ...rest) {
  try { velorSetConstant(false, chain, value, rest); } catch (_) { /* never break the page */ }
}

// trusted-set-constant(chain, value, …): set-constant without the value
// restrictions — JSON objects, arrays and arbitrary strings included.
function trustedSetConstant(chain, value, ...rest) {
  try { velorSetConstant(true, chain, value, rest); } catch (_) { /* never break the page */ }
}

// abort-on-property-read(chain): reading the property throws into the
// accessing script; writes are swallowed.
function abortOnPropertyRead(chain) {
  try {
    velorOnChain(globalThis, chain, (owner, key) => {
      Object.defineProperty(owner, key, { configurable: true, get() { throw velorAbortError(); }, set() {} });
    });
  } catch (_) { /* never break the page */ }
}

// abort-on-property-write(chain): writing the property throws; reads keep
// returning what is there.
function abortOnPropertyWrite(chain) {
  try {
    velorOnChain(globalThis, chain, (owner, key, descriptor) => {
      Object.defineProperty(owner, key, {
        configurable: true,
        get() { return descriptor ? (descriptor.get ? descriptor.get.call(this) : descriptor.value) : undefined; },
        set() { throw velorAbortError(); }
      });
    });
  } catch (_) { /* never break the page */ }
}

// abort-current-script(chain, needle, context): accessing the property from
// a script whose text matches `needle` (and whose decoded src matches
// `context`, when given) throws. Access outside any running script element
// is left alone.
function abortCurrentScript(chain, needle, context) {
  try {
    const matchesText = velorMatcher(needle, false);
    const matchesSource = velorMatcher(context, false);
    if (!matchesText || !matchesSource) return;
    velorGuardChain(chain, () => {
      const script = document.currentScript;
      if (!script || typeof script !== "object") return;
      let source = String(script.src || "");
      if (context && /^data:/i.test(source)) {
        try {
          const comma = source.indexOf(",");
          const payload = source.slice(comma + 1);
          source = /;base64/i.test(source.slice(0, comma)) ? atob(payload) : decodeURIComponent(payload);
        } catch (_) { /* match the raw src instead */ }
      }
      if (matchesSource(source) && matchesText(script.textContent || "")) throw velorAbortError();
    });
  } catch (_) { /* never break the page */ }
}

// abort-on-stack-trace(chain, needle): accessing the property while the
// call stack matches throws. An empty needle only logs in uBO, so it does
// nothing here.
function abortOnStackTrace(chain, needle) {
  try {
    if (!needle) return;
    const matches = velorStackMatcher(needle);
    if (!matches) return;
    velorGuardChain(chain, () => { if (matches()) throw velorAbortError(); });
  } catch (_) { /* never break the page */ }
}

// no-setTimeout-if(needle, delay)
function noSetTimeoutIf(needle, delay) {
  try { velorDefuseTimer("setTimeout", needle, delay); } catch (_) { /* never break the page */ }
}

// no-setInterval-if(needle, delay)
function noSetIntervalIf(needle, delay) {
  try { velorDefuseTimer("setInterval", needle, delay); } catch (_) { /* never break the page */ }
}

// adjust-setTimeout(needle, delay, boost)
function adjustSetTimeout(needle, delay, boost) {
  try { velorAdjustTimer("setTimeout", needle, delay, boost); } catch (_) { /* never break the page */ }
}

// adjust-setInterval(needle, delay, boost)
function adjustSetInterval(needle, delay, boost) {
  try { velorAdjustTimer("setInterval", needle, delay, boost); } catch (_) { /* never break the page */ }
}

// addEventListener-defuser(type, handler): registrations whose event type
// and stringified listener both match (each "!" negatable, "" is any) are
// dropped.
function addEventListenerDefuser(type, handler) {
  try {
    const matchesType = velorMatcher(type, true);
    const matchesHandler = velorMatcher(handler, true);
    const proto = globalThis.EventTarget && globalThis.EventTarget.prototype;
    if (!matchesType || !matchesHandler || !proto || typeof proto.addEventListener !== "function") return;
    const native = proto.addEventListener;
    proto.addEventListener = velorMaskNative(function (eventType, listener) {
      let skip = false;
      try {
        skip = matchesType(eventType) && matchesHandler(typeof listener === "function" ? String(listener) : listener);
      } catch (_) { /* register as usual */ }
      if (!skip) return native.apply(this, arguments);
      return undefined;
    }, native);
  } catch (_) { /* never break the page */ }
}

// no-window-open-if(pattern, delay, decoy): window.open calls whose
// arguments (joined by spaces) match `pattern` ("!" negatable, "" is any)
// are not made. They return null, or a sham window object when `delay` is
// a number (uBO would remove its decoy after that many seconds; the sham
// here is inert so there is nothing to remove). AdGuard's legacy form
// ("0"|"1", search) is accepted. The decoy kind is ignored.
function noWindowOpenIf(pattern, delay) {
  try {
    let needle = pattern == null ? "" : String(pattern);
    let sham = String(delay == null ? "" : delay).trim() !== "" && Number.isFinite(Number(delay));
    if (needle === "0" || needle === "1") {
      needle = (needle === "0" ? "!" : "") + String(delay == null ? "" : delay);
      sham = true;
    }
    const matches = velorMatcher(needle, true);
    const native = globalThis.open;
    if (!matches || typeof native !== "function") return;
    const fakeWindow = (url) => {
      const noop = () => {};
      const fake = {
        closed: false, opener: null, name: "", focus: noop, blur: noop, postMessage: noop, moveTo: noop, moveBy: noop,
        resizeTo: noop, resizeBy: noop, addEventListener: noop, removeEventListener: noop, dispatchEvent: () => false,
        close() { fake.closed = true; },
        location: { href: url, assign: noop, replace: noop, reload: noop, toString: () => url },
        document: { write: noop, writeln: noop, open: noop, close: noop, body: null, head: null, title: "" }
      };
      return fake;
    };
    globalThis.open = velorMaskNative(function () {
      let prevent = false;
      try { prevent = matches(Array.prototype.map.call(arguments, String).join(" ")); } catch (_) { /* open as usual */ }
      if (!prevent) return native.apply(this, arguments);
      return sham ? fakeWindow(arguments.length ? String(arguments[0]) : "") : null;
    }, native);
  } catch (_) { /* never break the page */ }
}

// no-fetch-if(propsToMatch, responseBody, responseType): matching fetches
// resolve with a synthetic 200 response (body "{}" by default) instead of
// going out. `responseType` is a type name or a JSON object with ok, type,
// status, statusText, redirected.
function noFetchIf(propsToMatch, responseBody, responseType) {
  try {
    const matches = velorRequestMatcher(propsToMatch);
    const native = globalThis.fetch;
    if (!matches || typeof native !== "function") return;
    const body = velorResponseBody(responseBody, "{}");
    let config = {};
    const typeText = String(responseType == null ? "" : responseType).trim();
    if (typeText.startsWith("{")) {
      try { config = JSON.parse(typeText); } catch (_) { config = {}; }
    } else if (typeText) {
      config = { type: typeText };
    }
    globalThis.fetch = velorMaskNative(function (input, init) {
      let url = "";
      let prevent = false;
      try {
        const props = velorFetchProps(input, init);
        url = props.url;
        prevent = matches(props);
      } catch (_) { prevent = false; }
      if (!prevent) return native.apply(this, arguments);
      let response;
      try {
        response = new Response(body, {
          status: Number.isInteger(config.status) ? config.status : 200,
          statusText: typeof config.statusText === "string" ? config.statusText : "OK",
          headers: { "Content-Type": body === "{}" || body === "[]" ? "application/json" : "text/plain" }
        });
      } catch (_) {
        return native.apply(this, arguments);
      }
      try {
        Object.defineProperty(response, "url", { value: url, configurable: true });
        for (const key of ["type", "ok", "redirected"]) {
          if (config[key] !== undefined) Object.defineProperty(response, key, { value: config[key], configurable: true });
        }
      } catch (_) { /* a plain response is still a response */ }
      return Promise.resolve(response);
    }, native);
  } catch (_) { /* never break the page */ }
}

// no-xhr-if(propsToMatch, directive): matching requests are never sent;
// the XHR completes asynchronously as a 200 with an empty body (or the
// filler `directive` asks for) and fires readystatechange, load, loadend.
function noXhrIf(propsToMatch, directive) {
  try {
    const matches = velorRequestMatcher(propsToMatch);
    const proto = globalThis.XMLHttpRequest && globalThis.XMLHttpRequest.prototype;
    if (!matches || !proto || typeof proto.open !== "function" || typeof proto.send !== "function") return;
    const body = velorResponseBody(directive, "");
    const pending = new WeakMap();
    const open = proto.open;
    const send = proto.send;
    proto.open = velorMaskNative(function (method, url) {
      try {
        const props = { method: String(method), url: String(url), async: arguments.length > 2 ? String(arguments[2]) : "true" };
        if (matches(props)) pending.set(this, props);
        else pending.delete(this);
      } catch (_) { pending.delete(this); }
      return open.apply(this, arguments);
    }, open);
    proto.send = velorMaskNative(function () {
      const props = pending.get(this);
      if (!props) return send.apply(this, arguments);
      const xhr = this;
      Promise.resolve().then(() => {
        try {
          const type = xhr.responseType;
          let response = body;
          if (type === "json") response = body ? JSON.parse(body) : null;
          else if (type === "arraybuffer") response = new ArrayBuffer(0);
          else if (type === "blob") response = typeof Blob === "function" ? new Blob([]) : null;
          else if (type === "document") response = null;
          const own = (value) => ({ value, configurable: true, writable: true });
          Object.defineProperties(xhr, {
            readyState: own(4), status: own(200), statusText: own("OK"), responseURL: own(props.url),
            response: own(response), responseText: own(body), responseXML: own(null),
            getAllResponseHeaders: own(() => ""), getResponseHeader: own(() => null)
          });
          for (const name of ["readystatechange", "load", "loadend"]) xhr.dispatchEvent(new Event(name));
        } catch (_) { /* the request simply never completes */ }
      });
      return undefined;
    }, send);
  } catch (_) { /* never break the page */ }
}

// json-prune(propsToRemove, requiredProps, stack): JSON.parse and
// Response.prototype.json results lose the listed paths (space separated;
// "*" any key, "[]" each array element, a bare "*" everything) when every
// required path is present and the call stack matches.
function jsonPrune(propsToRemove, requiredProps, stack) {
  try {
    const remove = String(propsToRemove == null ? "" : propsToRemove).trim().split(/\s+/).filter(Boolean);
    const required = String(requiredProps == null ? "" : requiredProps).trim().split(/\s+/).filter(Boolean);
    const onStack = stack ? velorStackMatcher(stack) : null;
    if (remove.length === 0) return;
    const prune = (root) => {
      try {
        if (root === null || typeof root !== "object") return root;
        if (onStack && !onStack()) return root;
        if (!required.every((path) => velorPrunePath(root, path, false))) return root;
        for (const path of remove) velorPrunePath(root, path, true);
      } catch (_) { /* hand back what we have */ }
      return root;
    };
    const parse = JSON.parse;
    JSON.parse = velorMaskNative(function () { return prune(parse.apply(this, arguments)); }, parse);
    const proto = globalThis.Response && globalThis.Response.prototype;
    if (proto && typeof proto.json === "function") {
      const json = proto.json;
      proto.json = velorMaskNative(function () { return json.apply(this, arguments).then(prune); }, json);
    }
  } catch (_) { /* never break the page */ }
}

// remove-attr(attrs, selector, behavior): removes the |-separated attributes
// from elements matching `selector` (default: elements carrying them), now
// and as the DOM changes; see velorWatchDom for "stay" and "complete".
function removeAttr(attrs, selector, behavior) {
  try {
    const names = String(attrs == null ? "" : attrs).split("|").map((name) => name.trim()).filter(Boolean);
    if (names.length === 0) return;
    const query = String(selector == null ? "" : selector).trim() || names.map((name) => `[${name}]`).join(",");
    velorWatchDom(() => {
      for (const element of document.querySelectorAll(query)) {
        for (const name of names) element.removeAttribute(name);
      }
    }, behavior, { childList: true, subtree: true, attributes: true, attributeFilter: names });
  } catch (_) { /* never break the page */ }
}

// remove-class(classes, selector, behavior): like remove-attr for
// |-separated class names (default selector: elements carrying them).
function removeClass(classes, selector, behavior) {
  try {
    const names = String(classes == null ? "" : classes).split("|").map((name) => name.trim()).filter(Boolean);
    if (names.length === 0) return;
    const escape = (name) => (globalThis.CSS && typeof CSS.escape === "function" ? CSS.escape(name) : name);
    const query = String(selector == null ? "" : selector).trim() || names.map((name) => "." + escape(name)).join(",");
    velorWatchDom(() => {
      for (const element of document.querySelectorAll(query)) element.classList.remove(...names);
    }, behavior, { childList: true, subtree: true, attributes: true, attributeFilter: ["class"] });
  } catch (_) { /* never break the page */ }
}

// remove-node-text(nodeName, needle): empties the text of nodes named
// `nodeName` (lower-case, or a /regex/; "#text" for text nodes) whose text
// matches `needle`, as the parser adds them, so a matching inline script
// never runs.
function removeNodeText(nodeName, needle) {
  try {
    const name = String(nodeName == null ? "" : nodeName).trim();
    const isRegex = /^\/(.+)\/([a-z]*)$/.test(name);
    const matchesName = isRegex ? velorMatcher(name, false) : (candidate) => candidate === name.toLowerCase();
    const matchesText = velorMatcher(needle, false);
    if (!name || !matchesName || !matchesText) return;
    const strip = (node) => {
      if (node && matchesName(String(node.nodeName).toLowerCase()) && matchesText(node.textContent || "")) node.textContent = "";
    };
    new MutationObserver((records) => {
      for (const record of records) for (const node of record.addedNodes) strip(node);
    }).observe(document, { childList: true, subtree: true });
    if (!isRegex && !name.startsWith("#") && document.documentElement) {
      for (const node of document.querySelectorAll(name)) strip(node);
    }
  } catch (_) { /* never break the page */ }
}

// prevent-element-src-loading(tagName, needle): script/img/iframe/link
// elements whose src (href for link) is set by script to a matching URL get
// a harmless data: URL instead, so load fires, error does not, and nothing
// is fetched. Both the property setter and setAttribute are covered.
function preventElementSrcLoading(tagName, needle) {
  try {
    const tag = String(tagName == null ? "" : tagName).trim().toLowerCase();
    const matches = velorMatcher(needle, false);
    const constructors = { script: "HTMLScriptElement", img: "HTMLImageElement", iframe: "HTMLIFrameElement", link: "HTMLLinkElement" };
    const mocks = {
      script: "data:text/javascript;base64,KCk9Pnt9",
      img: "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
      iframe: "data:text/html;base64,PGh0bWw+PC9odG1sPg==",
      link: "data:text/css;base64,"
    };
    const proto = constructors[tag] && globalThis[constructors[tag]] && globalThis[constructors[tag]].prototype;
    if (!matches || !proto) return;
    const attribute = tag === "link" ? "href" : "src";
    const mock = mocks[tag];
    const descriptor = Object.getOwnPropertyDescriptor(proto, attribute);
    if (descriptor && descriptor.set && descriptor.configurable) {
      Object.defineProperty(proto, attribute, { ...descriptor, set(value) { descriptor.set.call(this, matches(value) ? mock : value); } });
    }
    const elementProto = globalThis.Element && globalThis.Element.prototype;
    if (elementProto && typeof elementProto.setAttribute === "function") {
      const setAttribute = elementProto.setAttribute;
      elementProto.setAttribute = velorMaskNative(function (name, value) {
        try {
          if (String(this.localName).toLowerCase() === tag && String(name).toLowerCase() === attribute && matches(value)) arguments[1] = mock;
        } catch (_) { /* set as usual */ }
        return setAttribute.apply(this, arguments);
      }, setAttribute);
    }
  } catch (_) { /* never break the page */ }
}

// set-cookie(name, value, path): sets a session cookie, but only to one of
// the documented harmless values (consent/dismissal words, emptyArr,
// emptyObj, integers within ±32767). `path` is "/" (default) or "none".
function setCookie(name, value, path) {
  try {
    const safe = velorSafeCookieValue(value);
    if (safe !== null) velorSetCookie(name, safe, { path });
  } catch (_) { /* never break the page */ }
}

// set-cookie-reload(name, value, path): set-cookie, then one reload once the
// cookie is in place (none if it already was).
function setCookieReload(name, value, path) {
  try {
    const safe = velorSafeCookieValue(value);
    if (safe !== null) velorSetCookie(name, safe, { path, reload: true });
  } catch (_) { /* never break the page */ }
}

// trusted-set-cookie(name, value, offsetExpiresSec, path, …): set-cookie
// with any value, an optional expiry and domain; see velorTrustedSetCookie.
function trustedSetCookie(name, value, offsetExpiresSec, path, ...rest) {
  try { velorTrustedSetCookie(name, value, offsetExpiresSec, path, rest, false); } catch (_) { /* never break the page */ }
}

// trusted-set-cookie-reload(name, value, offsetExpiresSec, path, …)
function trustedSetCookieReload(name, value, offsetExpiresSec, path, ...rest) {
  try { velorTrustedSetCookie(name, value, offsetExpiresSec, path, rest, true); } catch (_) { /* never break the page */ }
}

// remove-cookie(needle, "when", events): expires cookies whose name matches
// `needle` ("" is all), now, before unload, and after each listed event,
// for the current path and host and every parent domain.
function removeCookie(needle, when, events) {
  try {
    const matches = velorMatcher(needle, false);
    if (!matches) return;
    const remove = () => {
      try {
        const host = String((globalThis.location && globalThis.location.hostname) || "");
        const labels = host.split(".");
        const domains = [""];
        for (let i = 0; i < labels.length - 1; i += 1) domains.push(labels.slice(i).join("."));
        const paths = ["/", String((globalThis.location && globalThis.location.pathname) || "/")];
        for (const entry of String(document.cookie).split(";")) {
          const name = entry.split("=")[0].trim();
          if (!name || !matches(name)) continue;
          for (const domain of domains) {
            for (const path of paths) {
              document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=${path}${domain ? `; domain=${domain}` : ""}`;
            }
          }
        }
      } catch (_) { /* cookies may be inaccessible */ }
    };
    remove();
    globalThis.addEventListener("beforeunload", remove);
    if (when === "when") {
      for (const type of String(events == null ? "" : events).split(/\s+/).filter(Boolean)) {
        globalThis.addEventListener(type, remove, { passive: true });
      }
    }
  } catch (_) { /* never break the page */ }
}

// set-local-storage-item(key, value)
function setLocalStorageItem(key, value) {
  try { velorSetStorageItem(globalThis.localStorage, key, value); } catch (_) { /* storage may be unavailable */ }
}

// set-session-storage-item(key, value)
function setSessionStorageItem(key, value) {
  try { velorSetStorageItem(globalThis.sessionStorage, key, value); } catch (_) { /* storage may be unavailable */ }
}

// trusted-set-local-storage-item(key, value): any value, with $now$,
// $currentDate$ and $currentISODate$ expanded.
function trustedSetLocalStorageItem(key, value) {
  try { velorSetStorageItem(globalThis.localStorage, key, value, true); } catch (_) { /* storage may be unavailable */ }
}

// trusted-set-session-storage-item(key, value)
function trustedSetSessionStorageItem(key, value) {
  try { velorSetStorageItem(globalThis.sessionStorage, key, value, true); } catch (_) { /* storage may be unavailable */ }
}

// href-sanitizer(selector, source, transform): rewrites the href of anchors
// matching `selector` to the real destination found by `source`: "text"
// (default, the link text), "?param" (a query parameter of the href),
// "[attr]" (an attribute), chained by spaces, with "-base64" (or AdGuard's
// third-argument "base64decode") decoding the result. Only an http(s) URL
// is ever written.
function hrefSanitizer(selector, source, transform) {
  try {
    const query = String(selector == null ? "" : selector).trim();
    if (!query) return;
    const steps = String(source == null ? "" : source).trim().split(/\s+/).filter(Boolean);
    if (steps.length === 0) steps.push("text");
    const extra = String(transform == null ? "" : transform).trim();
    if (extra === "base64decode" || extra === "-base64") steps.push("-base64");
    const done = new WeakSet();
    const resolve = (anchor) => {
      let current = anchor.getAttribute("href") || "";
      for (const step of steps) {
        if (step === "text") current = String(anchor.textContent || "").trim();
        else if (step.startsWith("?")) current = new URL(current, document.baseURI || location.href).searchParams.get(step.slice(1)) || "";
        else if (step.startsWith("[") && step.endsWith("]")) current = anchor.getAttribute(step.slice(1, -1)) || "";
        else if (step === "-base64") current = atob(current.replace(/-/g, "+").replace(/_/g, "/").replace(/[^A-Za-z0-9+/=]/g, ""));
        else return "";
        if (!current) return "";
      }
      return /^https?:\/\//i.test(current) ? new URL(current).href : "";
    };
    velorWatchDom(() => {
      for (const anchor of document.querySelectorAll(query)) {
        if (done.has(anchor)) continue;
        done.add(anchor);
        let target = "";
        try { target = resolve(anchor); } catch (_) { target = ""; }
        if (target && target !== anchor.getAttribute("href")) anchor.setAttribute("href", target);
      }
    }, "stay", { childList: true, subtree: true });
  } catch (_) { /* never break the page */ }
}

// nowebrtc(): RTCPeerConnection and its prefixed forms become an inert
// constructor whose methods do nothing, so pages feature-detecting WebRTC
// still see a constructor but no connection is ever made.
function nowebrtc() {
  try {
    const noop = function () {};
    const settled = function () { return Promise.resolve(); };
    const Inert = function RTCPeerConnection() {};
    Object.assign(Inert.prototype, {
      close: noop, addIceCandidate: settled, createOffer: settled, createAnswer: settled, setLocalDescription: settled,
      setRemoteDescription: settled, getStats: settled, addTrack: noop, removeTrack: noop, addStream: noop,
      getSenders: () => [], getReceivers: () => [], getTransceivers: () => [], addEventListener: noop,
      removeEventListener: noop, dispatchEvent: () => false,
      createDataChannel: () => ({ close: noop, send: noop, addEventListener: noop, removeEventListener: noop })
    });
    for (const name of ["RTCPeerConnection", "webkitRTCPeerConnection", "mozRTCPeerConnection"]) {
      if (typeof globalThis[name] === "function") globalThis[name] = Inert;
    }
  } catch (_) { /* never break the page */ }
}

// noeval-if(needle)
function noevalIf(needle) {
  try { velorDefuseEval(needle); } catch (_) { /* never break the page */ }
}

// noeval(): every evaluation returns undefined.
function noeval() {
  try { velorDefuseEval(""); } catch (_) { /* never break the page */ }
}

// no-requestAnimationFrame-if(needle): matching callbacks ("!" negatable)
// are replaced by a no-op; the page still gets a frame id.
function noRequestAnimationFrameIf(needle) {
  try {
    const matches = velorMatcher(needle, true);
    const native = globalThis.requestAnimationFrame;
    if (!matches || typeof native !== "function") return;
    globalThis.requestAnimationFrame = velorMaskNative(function (callback) {
      let defuse = false;
      try { defuse = matches(typeof callback === "function" ? String(callback) : callback); } catch (_) { /* keep it */ }
      if (defuse) arguments[0] = function () {};
      return native.apply(this, arguments);
    }, native);
  } catch (_) { /* never break the page */ }
}

// json-prune-fetch-response(propsToRemove, requiredProps, …): the JSON body
// of fetch responses whose request matches the conditions (uBO's
// "propsToMatch" pair or AdGuard's positional third argument; "" is every
// request) loses the listed json-prune paths when every required path is
// present and the call stack matches ("stackToMatch" pair or positional
// fourth argument). A body that is not JSON, or has nothing to prune, is
// handed back untouched.
function jsonPruneFetchResponse(propsToRemove, requiredProps, ...rest) {
  try {
    const remove = String(propsToRemove == null ? "" : propsToRemove).trim().split(/\s+/).filter(Boolean);
    const required = String(requiredProps == null ? "" : requiredProps).trim().split(/\s+/).filter(Boolean);
    const options = velorPruneOptions(rest);
    const matches = velorRequestMatcher(options.propsToMatch);
    const onStack = options.stack ? velorStackMatcher(options.stack) : null;
    if (remove.length === 0 || !matches || (options.stack && !onStack)) return;
    velorRewriteFetch((props) => matches(props) && (!onStack || onStack()), (response) => response.clone().json().then((data) => {
      if (data === null || typeof data !== "object") return response;
      if (!required.every((path) => velorPrunePath(data, path, false))) return response;
      let pruned = false;
      for (const path of remove) if (velorPrunePath(data, path, true)) pruned = true;
      return pruned ? velorReplaceResponseBody(response, JSON.stringify(data)) : response;
    }));
  } catch (_) { /* never break the page */ }
}

// json-prune-xhr-response(propsToRemove, requiredProps, …): the same for
// XMLHttpRequest — the response text (or parsed object, for responseType
// json) is pruned as the page reads it.
function jsonPruneXhrResponse(propsToRemove, requiredProps, ...rest) {
  try {
    const remove = String(propsToRemove == null ? "" : propsToRemove).trim().split(/\s+/).filter(Boolean);
    const required = String(requiredProps == null ? "" : requiredProps).trim().split(/\s+/).filter(Boolean);
    const options = velorPruneOptions(rest);
    const matches = velorRequestMatcher(options.propsToMatch);
    const onStack = options.stack ? velorStackMatcher(options.stack) : null;
    if (remove.length === 0 || !matches || (options.stack && !onStack)) return;
    const prune = (data) => {
      if (data === null || typeof data !== "object") return false;
      if (!required.every((path) => velorPrunePath(data, path, false))) return false;
      let pruned = false;
      for (const path of remove) if (velorPrunePath(data, path, true)) pruned = true;
      return pruned;
    };
    velorRewriteXhr((props) => matches(props) && (!onStack || onStack()), (value) => {
      if (typeof value === "string") {
        let data;
        try { data = JSON.parse(value); } catch (_) { return value; }
        return prune(data) ? JSON.stringify(data) : value;
      }
      if (value !== null && typeof value === "object") prune(value);
      return value;
    });
  } catch (_) { /* never break the page */ }
}

// xml-prune(selector, selectorCheck, urlPattern): XML documents fetched (or
// loaded by XHR) from URLs matching `urlPattern` ("" is any) lose the nodes
// `selector` names — a CSS selector, or "xpath(…)" whose results may also
// be attributes — provided `selectorCheck`, when given, matches something
// in the document. Text that is not XML, or in which nothing matched, is
// passed through byte for byte rather than re-serialized.
function xmlPrune(selector, selectorCheck, urlPattern) {
  try {
    const query = String(selector == null ? "" : selector).trim();
    const check = String(selectorCheck == null ? "" : selectorCheck).trim();
    const matchesUrl = velorMatcher(urlPattern, false);
    if (!query || !matchesUrl) return;
    const xpath = /^xpath\((.+)\)$/s.exec(query);
    const select = (doc) => {
      if (!xpath) return Array.from(doc.querySelectorAll(query));
      const result = doc.evaluate(xpath[1], doc, null, XPathResult.UNORDERED_NODE_SNAPSHOT_TYPE, null);
      const nodes = [];
      for (let i = 0; i < result.snapshotLength; i += 1) nodes.push(result.snapshotItem(i));
      return nodes;
    };
    const pruneDocument = (doc) => {
      if (check && !doc.querySelector(check)) return false;
      let pruned = false;
      for (const node of select(doc)) {
        if (node.nodeType === 1) node.remove();
        else if (node.nodeType === 2 && node.ownerElement) node.ownerElement.removeAttribute(node.nodeName);
        else continue;
        pruned = true;
      }
      return pruned;
    };
    const pruneText = (text) => {
      if (!/^\s*</.test(text) || !/>\s*$/.test(text)) return text;
      const doc = new DOMParser().parseFromString(text, "text/xml");
      return pruneDocument(doc) ? new XMLSerializer().serializeToString(doc) : text;
    };
    const matches = (props) => matchesUrl(props.url);
    velorRewriteFetch(matches, (response) => response.clone().text().then((text) => {
      const after = pruneText(text);
      return after === text ? response : velorReplaceResponseBody(response, after);
    }));
    velorRewriteXhr(matches, (value) => {
      if (typeof value === "string") return pruneText(value);
      if (value !== null && typeof value === "object" && typeof value.querySelectorAll === "function") pruneDocument(value);
      return value;
    });
  } catch (_) { /* never break the page */ }
}

// m3u-prune(pattern, urlPattern): HLS playlists fetched (or loaded by XHR as
// text) from URLs matching `urlPattern` ("" is any) lose the parts
// `pattern` picks out — an #EXTINF entry whose URL line matches, with a
// following #EXT-X-DISCONTINUITY (uBO's rule), or a matching tag line
// together with everything up to the next tag of that name or a structural
// tag (AdGuard's rule, which is how its lists target #UPLYNK-SEGMENT ad
// blocks) — plus every #EXT-X-CUE SpliceOut block. Playlists the pattern
// does not occur in, and anything not starting with #EXTM3U, are untouched.
function m3uPrune(pattern, urlPattern) {
  try {
    const text = String(pattern == null ? "" : pattern).trim();
    const matchesLine = text ? velorMatcher(text, false) : null;
    const matchesUrl = velorMatcher(urlPattern, false);
    if (!matchesLine || !matchesUrl) return;
    const structural = ["#EXT-X-TARGETDURATION", "#EXT-X-MEDIA-SEQUENCE", "#EXT-X-DISCONTINUITY-SEQUENCE", "#EXT-X-ENDLIST",
      "#EXT-X-PLAYLIST-TYPE", "#EXT-X-I-FRAMES-ONLY", "#EXT-X-MEDIA", "#EXT-X-STREAM-INF", "#EXT-X-I-FRAME-STREAM-INF",
      "#EXT-X-SESSION-DATA", "#EXT-X-SESSION-KEY", "#EXT-X-INDEPENDENT-SEGMENTS", "#EXT-X-START"];
    const prune = (playlist) => {
      if (!/^\s*#EXTM3U/.test(playlist) || !matchesLine(playlist)) return playlist;
      const lines = playlist.split(/\r?\n|\r/);
      let changed = false;
      const drop = (index) => { lines[index] = undefined; changed = true; };
      const dropRun = (start, prefixes) => {
        let index = start;
        for (const prefix of prefixes) if (index < lines.length && lines[index] !== undefined && lines[index].startsWith(prefix)) drop(index++);
      };
      for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i];
        if (line === undefined || !line.startsWith("#")) continue;
        if (line.startsWith("#EXT-X-CUE:TYPE=\"SpliceOut\"")) {
          drop(i);
          dropRun(i + 1, ["#EXT-X-ASSET:CAID", "#EXT-X-SCTE35:", "#EXT-X-CUE-IN", "#EXT-X-SCTE35:"]);
        } else if (matchesLine(line)) {
          const colon = line.indexOf(":");
          if (colon <= 0) continue;
          const tag = line.slice(0, colon);
          drop(i);
          for (let j = i + 1; j < lines.length && lines[j] !== undefined && !lines[j].includes(tag) && !structural.some((prefix) => lines[j].startsWith(prefix)); j += 1) drop(j);
        } else if (line.startsWith("#EXTINF") && i + 1 < lines.length && !lines[i + 1].startsWith("#") && matchesLine(lines[i + 1])) {
          drop(i);
          drop(i + 1);
          dropRun(i + 2, ["#EXT-X-DISCONTINUITY"]);
        }
      }
      return changed ? lines.filter((line) => line !== undefined).join("\n") : playlist;
    };
    const matches = (props) => matchesUrl(props.url);
    velorRewriteFetch(matches, (response) => response.clone().text().then((before) => {
      const after = prune(before);
      return after === before ? response : velorReplaceResponseBody(response, after);
    }));
    velorRewriteXhr(matches, (value) => (typeof value === "string" ? prune(value) : value));
  } catch (_) { /* never break the page */ }
}

// set-attr(selector, attr, value): sets `attr` on elements matching
// `selector` to one of the permitted values — "" (default), true/false (as
// written), an integer 0–32767, or "[other]" to copy attribute `other` from
// the same element (skipped while it is absent) — now and as the DOM
// changes. Event handler attributes (on*) are never set.
function setAttr(selector, attr, value) {
  try {
    const query = String(selector == null ? "" : selector).trim();
    const name = String(attr == null ? "" : attr).trim();
    let text = String(value == null ? "" : value).trim();
    if (!query || !/^[a-zA-Z_:][-\w:.]*$/.test(name) || /^on/i.test(name)) return;
    let copy = "";
    if (/^\d+$/.test(text)) {
      if (Number(text) > 32767) return;
      text = String(Number(text));
    } else if (/^\[.+\]$/.test(text)) {
      copy = text.slice(1, -1);
    } else if (text !== "" && !/^(true|false)$/i.test(text)) {
      return;
    }
    velorWatchDom(() => {
      for (const element of document.querySelectorAll(query)) {
        const next = copy ? element.getAttribute(copy) : text;
        if (next !== null && element.getAttribute(name) !== next) element.setAttribute(name, next);
      }
    }, "stay", { childList: true, subtree: true });
  } catch (_) { /* never break the page */ }
}

// spoof-css(selector, property, value, …): getComputedStyle for elements
// matching `selector` reports the listed properties (kebab or camel case)
// as the given values, and their getBoundingClientRect uses spoofed width
// and height; everything else is read from the real style. Properties
// starting with "_" are uBO's debugging switches and are ignored.
function spoofCss(selector, ...pairs) {
  try {
    const query = String(selector == null ? "" : selector).trim();
    if (!query) return;
    const camel = (name) => String(name).replace(/-[a-z]/g, (dash) => dash.charAt(1).toUpperCase());
    const spoofed = new Map();
    for (let i = 0; i + 1 < pairs.length; i += 2) {
      const name = camel(String(pairs[i]).trim());
      if (name && !name.startsWith("_")) spoofed.set(name, String(pairs[i + 1]));
    }
    if (spoofed.size === 0) return;
    const targeted = (element) => {
      try { return element !== null && typeof element === "object" && typeof element.matches === "function" && element.matches(query); } catch (_) { return false; }
    };
    const computed = globalThis.getComputedStyle;
    if (typeof computed === "function") {
      globalThis.getComputedStyle = velorMaskNative(function (element) {
        const style = computed.apply(this, arguments);
        if (!targeted(element)) return style;
        return new Proxy(style, {
          get(target, property) {
            const value = Reflect.get(target, property);
            if (typeof value === "function") {
              if (property !== "getPropertyValue") return value.bind(target);
              return function getPropertyValue(name) { return spoofed.has(camel(name)) ? spoofed.get(camel(name)) : value.call(target, name); };
            }
            return typeof property === "string" && spoofed.has(camel(property)) ? spoofed.get(camel(property)) : value;
          },
          getOwnPropertyDescriptor(target, property) {
            if (typeof property === "string" && spoofed.has(camel(property))) {
              return { configurable: true, enumerable: true, writable: true, value: spoofed.get(camel(property)) };
            }
            return Reflect.getOwnPropertyDescriptor(target, property);
          }
        });
      }, computed);
    }
    const proto = globalThis.Element && globalThis.Element.prototype;
    if (proto && typeof proto.getBoundingClientRect === "function" && (spoofed.has("width") || spoofed.has("height"))) {
      const rect = proto.getBoundingClientRect;
      proto.getBoundingClientRect = velorMaskNative(function () {
        const real = rect.apply(this, arguments);
        if (!targeted(this)) return real;
        const width = spoofed.has("width") ? parseFloat(spoofed.get("width")) : real.width;
        const height = spoofed.has("height") ? parseFloat(spoofed.get("height")) : real.height;
        return new DOMRect(real.x, real.y, width, height);
      }, rect);
    }
  } catch (_) { /* never break the page */ }
}

// prevent-navigation(pattern): script-driven navigations — the Navigation
// API's navigate event, never one the user initiated — whose destination
// matches `pattern` ("!" negatable; "location.href" means the current URL)
// are cancelled. An empty pattern only logs in uBO, so it does nothing here.
function preventNavigation(pattern) {
  try {
    const text = String(pattern == null ? "" : pattern);
    const navigation = globalThis.navigation;
    if (!text || !navigation || typeof navigation.addEventListener !== "function") return;
    const matches = velorMatcher(text === "location.href" ? String(globalThis.location.href) : text, true);
    if (!matches) return;
    navigation.addEventListener("navigate", (event) => {
      try {
        if (event.userInitiated || !event.destination) return;
        if (matches(String(event.destination.url))) event.preventDefault();
      } catch (_) { /* let the navigation proceed */ }
    });
  } catch (_) { /* never break the page */ }
}

// refresh-defuser(delay): defuses a <meta http-equiv="refresh"> by stopping
// the page (window.stop) once it has loaded — after `delay` seconds when
// given, otherwise halfway through the meta's own delay, which only starts
// counting at load.
function refreshDefuser(delay) {
  try {
    const seconds = String(delay == null ? "" : delay).trim();
    if (seconds !== "" && !/^\d+(\.\d+)?$/.test(seconds)) return;
    const defuse = () => {
      try {
        const meta = document.querySelector("meta[http-equiv=\"refresh\" i][content]");
        if (!meta) return;
        const wait = seconds === "" ? Math.max(parseFloat(meta.getAttribute("content")) || 0, 0) * 500 : Number(seconds) * 1000;
        const stop = () => { try { globalThis.stop(); } catch (_) { /* nothing to stop */ } };
        if (wait === 0) stop();
        else globalThis.setTimeout(stop, wait);
      } catch (_) { /* no meta refresh to defuse */ }
    };
    globalThis.addEventListener("load", defuse, { capture: true, once: true });
  } catch (_) { /* never break the page */ }
}

// prevent-innerHTML(selector, pattern): assignments to innerHTML on elements
// matching `selector` ("" is any) whose new value matches `pattern` ("!"
// negatable, "" is any) are dropped; reads are untouched.
function preventInnerHTML(selector, pattern) {
  try {
    const query = String(selector == null ? "" : selector).trim();
    const matches = velorMatcher(pattern, true);
    const proto = globalThis.Element && globalThis.Element.prototype;
    const descriptor = proto && Object.getOwnPropertyDescriptor(proto, "innerHTML");
    if (!matches || !descriptor || !descriptor.set || !descriptor.configurable) return;
    Object.defineProperty(proto, "innerHTML", { ...descriptor, set(value) {
      let prevent = false;
      try {
        prevent = (!query || (typeof this.matches === "function" && this.matches(query))) && matches(String(value));
      } catch (_) { prevent = false; }
      if (!prevent) descriptor.set.call(this, value);
    } });
  } catch (_) { /* never break the page */ }
}

// hide-in-shadow-dom(selector, baseSelector): elements matching `selector`
// inside open shadow roots (under `baseSelector`, default the whole page)
// get display: none !important.
function hideInShadowDom(selector, baseSelector) {
  try {
    velorInShadowDom(selector, baseSelector, (element) => {
      const style = element.style;
      if (!style || (style.getPropertyValue("display") === "none" && style.getPropertyPriority("display") === "important")) return;
      style.setProperty("display", "none", "important");
    });
  } catch (_) { /* never break the page */ }
}

// remove-in-shadow-dom(selector, baseSelector): the same elements are
// removed instead.
function removeInShadowDom(selector, baseSelector) {
  try {
    velorInShadowDom(selector, baseSelector, (element) => element.remove());
  } catch (_) { /* never break the page */ }
}

// nobab(): defuses BlockAdBlock. Code handed to eval that carries its
// signature (its names, or most of the identifiers its obfuscated loader
// is built from) is not run — and the overlay it may already have shown is
// undone — while its string setTimeout callbacks naming bab_elementid are
// swapped for a no-op. Everything else evaluates as usual.
function nobab() {
  try {
    const signatures = [
      ["blockadblock"],
      ["babasbm"],
      [/getItem\('babn'\)/],
      ["getElementById", "String.fromCharCode", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "charAt",
        "DOMContentLoaded", "AdBlock", "addEventListener", "doScroll", "fromCharCode", "<<2|r>>4", "sessionStorage",
        "clientWidth", "localStorage", "Math", "random"]
    ];
    const looksLikeBab = (code) => typeof code === "string" && signatures.some((tokens) =>
      tokens.filter((token) => (token instanceof RegExp ? token.test(code) : code.includes(token))).length / tokens.length >= 0.8);
    const nativeEval = globalThis.eval;
    if (typeof nativeEval === "function") {
      globalThis.eval = velorMaskNative(function (code) {
        if (!looksLikeBab(code)) return nativeEval(code);
        try {
          if (document.body) document.body.style.removeProperty("visibility");
          const overlay = document.getElementById("babasbmsgx");
          if (overlay) overlay.remove();
        } catch (_) { /* nothing shown yet */ }
        return undefined;
      }, nativeEval);
    }
    const nativeTimeout = globalThis.setTimeout;
    if (typeof nativeTimeout === "function") {
      globalThis.setTimeout = velorMaskNative(function (callback) {
        if (typeof callback === "string" && /\.bab_elementid.$/.test(callback)) arguments[0] = function () {};
        return nativeTimeout.apply(this, arguments);
      }, nativeTimeout);
    }
  } catch (_) { /* never break the page */ }
}

// popads-dummy(): PopAds and popns become frozen empty objects the
// popads.net loader cannot replace, so it finds nothing to run.
function popadsDummy() {
  try {
    for (const name of ["PopAds", "popns"]) {
      const own = Object.getOwnPropertyDescriptor(globalThis, name);
      if (own && own.configurable === false) continue;
      Object.defineProperty(globalThis, name, { value: {}, writable: false, enumerable: false, configurable: false });
    }
  } catch (_) { /* never break the page */ }
}

// prevent-popads-net(): assigning PopAds or popns throws into the popads.net
// loader, and that one error is kept from the console and the page's error
// handlers, as the stand-ins do. Reads return undefined.
function preventPopadsNet() {
  try {
    const magic = Math.random().toString(36).slice(2);
    globalThis.addEventListener("error", (event) => {
      try {
        if (!String(event.message || (event.error && event.error.message) || "").includes(magic)) return;
        event.preventDefault();
        event.stopImmediatePropagation();
      } catch (_) { /* report it after all */ }
    }, true);
    for (const name of ["PopAds", "popns"]) {
      const own = Object.getOwnPropertyDescriptor(globalThis, name);
      if (own && own.configurable === false) continue;
      Object.defineProperty(globalThis, name, { configurable: true, get() { return undefined; }, set() { throw new ReferenceError(magic); } });
    }
  } catch (_) { /* never break the page */ }
}

// trusted-suppress-native-method(methodPath, signature, how, stack): calls
// of the named native method whose arguments match the |-separated
// signature are suppressed. Each position is a quoted "text" (substring, or
// /regex/ inside the quotes), a bare /regex/, true/false/null/undefined/NaN
// or a number (exact), {…} (a partial object, string fields by substring),
// […] (an unordered partial array) or a lone space to skip that argument.
// A suppressed call throws (`how` "abort", the default) or returns
// undefined ("prevent"; AdGuard treats any other word as prevent, so Velor
// does too). A signature that cannot be parsed installs nothing, and a
// `stack` needle must match the caller.
function trustedSuppressNativeMethod(methodPath, signature, how, stack) {
  try {
    const path = String(methodPath == null ? "" : methodPath).trim();
    const text = String(signature == null ? "" : signature);
    if (!path || !text.trim()) return;
    const pieces = text.split("|");
    const tokens = [];
    for (let i = 0; i < pieces.length; i += 1) {
      let token = pieces[i];
      while (/^\s*\/./.test(token) && !/^\s*\/.+\/[a-z]*\s*$/.test(token) && i + 1 < pieces.length) token += `|${pieces[++i]}`;
      tokens.push(token.trim());
    }
    const same = (a, b) => a === b || (Number.isNaN(a) && Number.isNaN(b));
    const matcherFor = (expected) => {
      if (typeof expected === "string") return (actual) => typeof actual === "string" && (expected === "" ? actual === "" : actual.includes(expected));
      if (Array.isArray(expected)) {
        const items = expected.map(matcherFor);
        return (actual) => Array.isArray(actual) && items.every((item) => actual.some((candidate) => item(candidate)));
      }
      if (expected !== null && typeof expected === "object") {
        const fields = Object.keys(expected).map((key) => [key, matcherFor(expected[key])]);
        return (actual) => actual !== null && (typeof actual === "object" || typeof actual === "function") && fields.every(([key, field]) => field(actual[key]));
      }
      return (actual) => same(actual, expected);
    };
    const parse = (token) => {
      if (token === "") return null;
      const quoted = /^"(.*)"$/s.exec(token);
      const regex = /^\/.+\/[a-z]*$/s.test(quoted ? quoted[1] : token) ? velorMatcher(quoted ? quoted[1] : token, false) : null;
      if (regex) return (actual) => typeof actual === "string" && regex(actual);
      if (/^\/.+\/[a-z]*$/s.test(quoted ? quoted[1] : token)) throw new SyntaxError(token);
      if (quoted) return matcherFor(quoted[1]);
      const keywords = { true: true, false: false, null: null, undefined, NaN };
      if (Object.prototype.hasOwnProperty.call(keywords, token)) return matcherFor(keywords[token]);
      if (/^-?\d+(\.\d+)?$/.test(token)) return matcherFor(Number(token));
      if (/^[[{]/.test(token)) return matcherFor(JSON.parse(token));
      throw new SyntaxError(token);
    };
    const matchers = tokens.map(parse);
    const onStack = stack ? velorStackMatcher(stack) : null;
    if (stack && !onStack) return;
    const abort = ["", "abort"].includes(String(how == null ? "" : how).trim());
    velorWrapMethod(path, (native, self, args) => {
      let hit = false;
      try {
        hit = matchers.every((matcher, index) => !matcher || matcher(args[index])) && (!onStack || onStack());
      } catch (_) { hit = false; }
      if (!hit) return native.apply(self, args);
      if (abort) throw velorAbortError();
      return undefined;
    });
  } catch (_) { /* never break the page */ }
}

// trusted-prune-inbound-object(functionPath, [argPos,] propsToRemove, requiredProps, stack):
// the object the named function receives — its first argument, or the
// 1-based `argPos` when the second argument is a number, as uBO writes it —
// loses the listed json-prune paths, in place, when every required path is
// present and the call stack matches ("stackToMatch" pair or positional).
function trustedPruneInboundObject(functionPath, ...rest) {
  try {
    let position = 0;
    if (/^\d+$/.test(String(rest[0] == null ? "" : rest[0]).trim())) position = Number(rest.shift()) - 1;
    if (position < 0) return;
    const remove = String(rest[0] == null ? "" : rest[0]).trim().split(/\s+/).filter(Boolean);
    const required = String(rest[1] == null ? "" : rest[1]).trim().split(/\s+/).filter(Boolean);
    const stack = rest[2] === "stackToMatch" ? rest[3] : rest[2];
    const onStack = stack ? velorStackMatcher(stack) : null;
    if (remove.length === 0 || (stack && !onStack)) return;
    velorWrapMethod(functionPath, (native, self, args) => {
      try {
        const target = args[position];
        if (target !== null && typeof target === "object" && (!onStack || onStack()) && required.every((path) => velorPrunePath(target, path, false))) {
          for (const path of remove) velorPrunePath(target, path, true);
        }
      } catch (_) { /* hand the object over untouched */ }
      return native.apply(self, args);
    });
  } catch (_) { /* never break the page */ }
}

// ------------------------------------------------------------------ tables

export const HELPERS = Object.freeze({
  velorMatcher, velorOnChain, velorGuardChain, velorAbortError, velorStackMatcher, velorMaskNative, velorRequestMatcher,
  velorResponseBody, velorPrunePath, velorWatchDom, velorDefuseTimer, velorAdjustTimer, velorSetStorageItem, velorDefuseEval,
  velorSetConstant, velorWrapMethod, velorFetchProps, velorRewriteFetch, velorReplaceResponseBody, velorRewriteXhr,
  velorSafeCookieValue, velorSetCookie, velorTimeKeywords, velorTrustedSetCookie, velorPruneOptions, velorInShadowDom
});

// Helpers that call other helpers; entries below list only direct needs
// and `expand` folds these in.
const HELPER_DEPENDENCIES = {
  velorGuardChain: ["velorOnChain"],
  velorStackMatcher: ["velorMatcher"],
  velorRequestMatcher: ["velorMatcher"],
  velorDefuseTimer: ["velorMatcher", "velorMaskNative"],
  velorAdjustTimer: ["velorMatcher", "velorMaskNative"],
  velorSetStorageItem: ["velorMatcher", "velorTimeKeywords"],
  velorDefuseEval: ["velorMatcher", "velorMaskNative"],
  velorSetConstant: ["velorOnChain", "velorStackMatcher"],
  velorWrapMethod: ["velorMaskNative"],
  velorRewriteFetch: ["velorMaskNative", "velorFetchProps"],
  velorRewriteXhr: ["velorMaskNative"],
  velorTrustedSetCookie: ["velorTimeKeywords", "velorSetCookie"]
};

function expand(names) {
  const ordered = [];
  const add = (name) => {
    if (ordered.includes(name)) return;
    for (const dependency of HELPER_DEPENDENCIES[name] || []) add(dependency);
    ordered.push(name);
  };
  names.forEach(add);
  return Object.freeze(ordered);
}

// Canonical name (uBO's, or AdGuard's for its own scriptlets) → [fn,
// helpers, aliases, options]. Aliases carry uBO's short forms and AdGuard's
// spellings; `scriptletFor` also accepts a trailing ".js". Options:
// `trusted` marks the trusted-* scriptlets the compiler takes only from
// uBlock Origin's and AdGuard's own lists; `resource` names a stand-in in
// extension/redirects/ that is injected as-is instead of a function.
const RESOURCE = (file, aliases) => [null, [], aliases, { resource: file }];
const TRUSTED = { trusted: true };
const ENTRIES = {
  "set-constant": [setConstant, ["velorSetConstant"], ["set"]],
  "abort-on-property-read": [abortOnPropertyRead, ["velorOnChain", "velorAbortError"], ["aopr"]],
  "abort-on-property-write": [abortOnPropertyWrite, ["velorOnChain", "velorAbortError"], ["aopw"]],
  "abort-current-script": [abortCurrentScript, ["velorMatcher", "velorGuardChain", "velorAbortError"],
    ["acs", "abort-current-inline-script", "acis"]],
  "abort-on-stack-trace": [abortOnStackTrace, ["velorStackMatcher", "velorGuardChain", "velorAbortError"], ["aost"]],
  "no-setTimeout-if": [noSetTimeoutIf, ["velorDefuseTimer"], ["nostif", "prevent-setTimeout", "setTimeout-defuser", "std"]],
  "no-setInterval-if": [noSetIntervalIf, ["velorDefuseTimer"], ["nosiif", "prevent-setInterval", "setInterval-defuser", "sid"]],
  "adjust-setTimeout": [adjustSetTimeout, ["velorAdjustTimer"], ["nano-setTimeout-booster", "nano-stb"]],
  "adjust-setInterval": [adjustSetInterval, ["velorAdjustTimer"], ["nano-setInterval-booster", "nano-sib"]],
  "addEventListener-defuser": [addEventListenerDefuser, ["velorMatcher", "velorMaskNative"], ["aeld", "prevent-addEventListener"]],
  "no-window-open-if": [noWindowOpenIf, ["velorMatcher", "velorMaskNative"], ["nowoif", "prevent-window-open", "window.open-defuser"]],
  "no-fetch-if": [noFetchIf, ["velorRequestMatcher", "velorResponseBody", "velorMaskNative", "velorFetchProps"], ["prevent-fetch"]],
  "no-xhr-if": [noXhrIf, ["velorRequestMatcher", "velorResponseBody", "velorMaskNative"], ["prevent-xhr"]],
  "json-prune": [jsonPrune, ["velorStackMatcher", "velorPrunePath", "velorMaskNative"], []],
  "remove-attr": [removeAttr, ["velorWatchDom"], ["ra"]],
  "remove-class": [removeClass, ["velorWatchDom"], ["rc"]],
  "remove-node-text": [removeNodeText, ["velorMatcher"], ["rmnt"]],
  "prevent-element-src-loading": [preventElementSrcLoading, ["velorMatcher", "velorMaskNative"], []],
  "set-cookie": [setCookie, ["velorSafeCookieValue", "velorSetCookie"], []],
  "set-cookie-reload": [setCookieReload, ["velorSafeCookieValue", "velorSetCookie"], []],
  "remove-cookie": [removeCookie, ["velorMatcher"], ["cookie-remover"]],
  "set-local-storage-item": [setLocalStorageItem, ["velorSetStorageItem"], []],
  "set-session-storage-item": [setSessionStorageItem, ["velorSetStorageItem"], []],
  "href-sanitizer": [hrefSanitizer, ["velorWatchDom"], []],
  nowebrtc: [nowebrtc, [], []],
  "noeval-if": [noevalIf, ["velorDefuseEval"], ["prevent-eval-if"]],
  noeval: [noeval, ["velorDefuseEval"], ["silent-noeval"]],
  "no-requestAnimationFrame-if": [noRequestAnimationFrameIf, ["velorMatcher", "velorMaskNative"], ["norafif", "prevent-requestAnimationFrame"]],
  "json-prune-fetch-response": [jsonPruneFetchResponse,
    ["velorPruneOptions", "velorRequestMatcher", "velorStackMatcher", "velorPrunePath", "velorRewriteFetch", "velorReplaceResponseBody"], []],
  "json-prune-xhr-response": [jsonPruneXhrResponse, ["velorPruneOptions", "velorRequestMatcher", "velorStackMatcher", "velorPrunePath", "velorRewriteXhr"], []],
  "xml-prune": [xmlPrune, ["velorMatcher", "velorRewriteFetch", "velorReplaceResponseBody", "velorRewriteXhr"], []],
  "m3u-prune": [m3uPrune, ["velorMatcher", "velorRewriteFetch", "velorReplaceResponseBody", "velorRewriteXhr"], []],
  "set-attr": [setAttr, ["velorWatchDom"], []],
  "spoof-css": [spoofCss, ["velorMaskNative"], []],
  "prevent-navigation": [preventNavigation, ["velorMatcher"], []],
  "refresh-defuser": [refreshDefuser, [], ["prevent-refresh"]],
  "prevent-innerHTML": [preventInnerHTML, ["velorMatcher"], []],
  "hide-in-shadow-dom": [hideInShadowDom, ["velorInShadowDom"], []],
  "remove-in-shadow-dom": [removeInShadowDom, ["velorInShadowDom"], []],
  nobab: [nobab, ["velorMaskNative"], ["prevent-bab", "bab-defuser"]],
  "popads-dummy": [popadsDummy, [], []],
  "prevent-popads-net": [preventPopadsNet, [], ["popads.net"]],
  "google-ima3": RESOURCE("google-ima.js", ["google-ima"]),
  "googletagservices-gpt": RESOURCE("googletagservices_gpt.js", ["googletagservices_gpt", "googletagservices.com/gpt"]),
  "amazon-apstag": RESOURCE("amazon_apstag.js", ["amazon_apstag"]),
  fingerprint2: RESOURCE("fingerprint2.js", []),
  nofab: RESOURCE("nofab.js", ["prevent-fab-3.2.0", "fuckadblock.js-3.2.0"]),
  "trusted-set-constant": [trustedSetConstant, ["velorSetConstant"], ["trusted-set"], TRUSTED],
  "trusted-set-cookie": [trustedSetCookie, ["velorTrustedSetCookie"], [], TRUSTED],
  "trusted-set-cookie-reload": [trustedSetCookieReload, ["velorTrustedSetCookie"], [], TRUSTED],
  "trusted-set-local-storage-item": [trustedSetLocalStorageItem, ["velorSetStorageItem"], [], TRUSTED],
  "trusted-set-session-storage-item": [trustedSetSessionStorageItem, ["velorSetStorageItem"], [], TRUSTED],
  "trusted-suppress-native-method": [trustedSuppressNativeMethod, ["velorMatcher", "velorStackMatcher", "velorWrapMethod", "velorAbortError"], [], TRUSTED],
  "trusted-prune-inbound-object": [trustedPruneInboundObject, ["velorStackMatcher", "velorPrunePath", "velorWrapMethod"], [], TRUSTED]
};

export const SCRIPTLETS = Object.freeze(Object.fromEntries(Object.entries(ENTRIES).map(([canonical, [fn, helpers, aliases, options = {}]]) =>
  [canonical, Object.freeze({
    fn, helpers: expand(helpers), aliases: Object.freeze(aliases), trusted: Boolean(options.trusted), resource: options.resource || null
  })])));

const INDEX = new Map(Object.entries(SCRIPTLETS).flatMap(([canonical, { aliases }]) =>
  [canonical, ...aliases].map((name) => [name, canonical])));

// Resolves a scriptlet name as written in a filter (uBO, uBO short alias,
// or AdGuard spelling, optionally with ".js") to `{ canonical, fn, helpers,
// trusted, resource }`: `helpers` are the helper functions to emit before
// `fn`, in order; `trusted` tells the compiler to accept the filter only
// from uBlock Origin's and AdGuard's own lists; for a resource-backed
// scriptlet `fn` is null, `helpers` empty and `resource` the file in
// extension/redirects/ to inject as-is. Returns null for anything Velor
// does not implement — trusted-* names included — so the compiler skips
// those filters.
export function scriptletFor(name) {
  if (typeof name !== "string") return null;
  const canonical = INDEX.get(name.trim().replace(/\.js$/, ""));
  if (!canonical) return null;
  const { fn, helpers, trusted, resource } = SCRIPTLETS[canonical];
  return { canonical, fn, helpers: helpers.map((helper) => HELPERS[helper]), trusted, resource };
}
