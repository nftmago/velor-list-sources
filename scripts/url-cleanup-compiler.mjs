import { isPublicHostname } from "./rule-compiler.mjs";

export const VELOR_PARAMS = Object.freeze([
  "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
  "utm_source_platform", "utm_creative_format", "utm_marketing_tactic", "fbclid", "gclid",
  "dclid", "gbraid", "wbraid", "msclkid", "twclid", "ttclid", "li_fat_id", "mc_cid",
  "mc_eid", "igshid", "yclid", "_hsenc", "_hsmi"
]);
export const MAX_CLEANUP_REGEX_RULES = 900;
const PARAM = /^[A-Za-z0-9_.%~-]{1,64}$/;
const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const related = (a, b) => a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);

export function parseRemoveparam(line) {
  const match = line.match(/^(.*?)\$(.+)$/);
  if (!match) return null;
  const options = match[2].split(",");
  const params = options.filter((option) => option.startsWith("removeparam="));
  if (params.length !== 1 || params[0].slice(12).startsWith("~") || !PARAM.test(params[0].slice(12))) return null;
  const types = options.filter((option) => !option.startsWith("removeparam="));
  if (types.some((type) => !["document", "subdocument"].includes(type))) return null;
  let host = "", path = "";
  if (match[1]) {
    const anchor = match[1].match(/^\|\|([^/^]+)(\^|\/[A-Za-z0-9/_.%~-]*)$/);
    if (!anchor || !isPublicHostname(anchor[1]) || anchor[1] !== anchor[1].toLowerCase()) return null;
    host = anchor[1];
    path = anchor[2] === "^" ? "" : anchor[2];
  }
  return { host, path, param: params[0].slice(12), resourceTypes: types.length
    ? [...new Set(types.map((type) => type === "document" ? "main_frame" : "sub_frame"))].sort()
    : ["main_frame", "sub_frame"] };
}

function exceptionScope(line) {
  const options = line.slice(line.lastIndexOf("$") + 1).split(",");
  const removal = options.find((option) => option === "removeparam" || option.startsWith("removeparam="));
  const param = removal?.slice(12);
  const host = line.match(/^@@\|\|([^/^]+)(?:\^|\/)/)?.[1];
  const initiators = options.find((option) => option.startsWith("domain="))?.slice(7).split("|");
  return {
    param: param && PARAM.test(param) ? param : null,
    host,
    exact: Boolean(host && isPublicHostname(host) && /^@@\|\|[^/^]+\^\$removeparam(?:=[A-Za-z0-9_.%~-]+)?$/.test(line)),
    initiators: initiators?.every(isPublicHostname) ? initiators : []
  };
}

export function compileUrlCleanup(source) {
  const lines = source.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("!") && !line.startsWith("["));
  const exceptions = lines.filter((line) => line.startsWith("@@") && line.includes("removeparam")).map(exceptionScope);
  const groups = new Map();
  let accepted = 0, rejected = 0;
  for (const line of lines.filter((line) => !line.startsWith("@@"))) {
    const parsed = parseRemoveparam(line);
    if (!parsed) { rejected++; continue; }
    const excludedRequestDomains = new Set();
    const excludedInitiatorDomains = new Set();
    let unsafe = false;
    for (const exception of exceptions) {
      if (exception.param && exception.param !== parsed.param) continue;
      if (exception.host) {
        if (isPublicHostname(exception.host)) {
          if (parsed.host && !related(parsed.host, exception.host)) continue;
          if (!exception.exact) { unsafe = true; break; }
          excludedRequestDomains.add(exception.host);
        } else {
          // A wildcard suffix can overlap an arbitrary subdomain of any host.
          // Compiled host rules are narrowed to the exact hostname below;
          // only prove disjointness for the common literal-prefix wildcard.
          const wildcard = exception.host.match(/^([a-z0-9.-]+)\.\*$/);
          if (parsed.host && wildcard && !new RegExp(`(?:^|\\.)${escapeRegex(wildcard[1])}\\.`).test(parsed.host)) continue;
          unsafe = true; break;
        }
      } else if (exception.initiators.length) {
        // Narrowing to exclude the whole initiator is safe even for a path exception.
        for (const host of exception.initiators) excludedInitiatorDomains.add(host);
      } else { unsafe = true; break; }
    }
    if (unsafe) { rejected++; continue; }
    const condition = { host: parsed.host, path: parsed.path, resourceTypes: parsed.resourceTypes,
      excludedRequestDomains: [...excludedRequestDomains].sort(), excludedInitiatorDomains: [...excludedInitiatorDomains].sort() };
    const key = JSON.stringify(condition);
    if (!groups.has(key)) groups.set(key, { ...condition, params: new Set() });
    groups.get(key).params.add(parsed.param);
    accepted++;
  }
  // The independent, pre-existing Velor policy remains intact. Upstream exceptions
  // govern the AdGuard derivative; they cannot silently revoke this local policy.
  const policies = [{ host: "", path: "", resourceTypes: ["main_frame", "sub_frame"], params: new Set(VELOR_PARAMS) }, ...[...groups.values()].filter((group) => !group.host), ...[...groups.values()].filter((group) => group.host)];
  const rules = [];
  let droppedForBudget = 0;
  for (const policy of policies) {
    const params = [...policy.params].sort();
    for (let offset = 0; offset < params.length; offset += 16) {
      const removeParams = params.slice(offset, offset + 16);
      const condition = {
        regexFilter: `^https?://[^/?#]+${policy.path ? escapeRegex(policy.path) : "(?:/|\\?)"}[^#]*[?&](${removeParams.map(escapeRegex).join("|")})=`,
        isUrlFilterCaseSensitive: true,
        resourceTypes: policy.resourceTypes
      };
      if (!policy.path) condition.regexFilter = `^https?://[^#]*[?&](${removeParams.map(escapeRegex).join("|")})=`;
      if (policy.host) {
        condition.requestDomains = [policy.host];
        // Exact host scope deliberately omits subdomains. Otherwise a wildcard
        // exception such as archive.* could overlap a tenant of any parent host.
        condition.regexFilter = `^https?://${escapeRegex(policy.host)}(:[0-9]+)?${policy.path ? escapeRegex(policy.path) : "/"}[^#]*[?&](${removeParams.map(escapeRegex).join("|")})=`;
      }
      for (const key of ["excludedRequestDomains", "excludedInitiatorDomains"]) if (policy[key]?.length) condition[key] = policy[key];
      // Above list exception allows (190) so they never stop link cleaning;
      // below cryptomining, $important blocks, threats and user choices.
      const rule = { id: rules.length + 1, priority: 195, action: { type: "redirect", redirect: { transform: { queryTransform: { removeParams } } } }, condition };
      if (Buffer.byteLength(JSON.stringify(rule)) >= 2048) { rejected += removeParams.length; continue; }
      if (rules.length >= MAX_CLEANUP_REGEX_RULES) { droppedForBudget++; continue; }
      rules.push(rule);
    }
  }
  return { rules, accepted, rejected, exceptions: exceptions.length, droppedForBudget, regexBudget: MAX_CLEANUP_REGEX_RULES };
}
