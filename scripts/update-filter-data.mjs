import { createHash } from "node:crypto";
import { readdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { applyListConditions, extractConservativeAbpDomains } from "../extension/lib/abp-compiler.js";
import { MAX_PRIVACY_LIST_BYTES, PRIVACY_SOURCES, privacyListFilterCount, validatePrivacyListText } from "../extension/lib/privacy-sources.js";
import { ANNOYANCE_SOURCES } from "../extension/lib/annoyance-sources.js";
import { REGIONAL_SOURCES } from "../extension/lib/regional-sources.js";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataDirectory = resolve(projectRoot, "filter-data");
const allowFeedJump = process.env.VELOR_ALLOW_FEED_JUMP === "1";

// The lists' URLs, expected headers and filter-count bounds live with the
// source tables: the ad and tracker lists (shared with the service worker's
// updater) and the optional annoyance and regional lists, which only
// releases update.
// Pass list ids to fetch only those (for example a newly added list).
const only = new Set(process.argv.slice(2));
const sources = [...PRIVACY_SOURCES, ...ANNOYANCE_SOURCES, ...REGIONAL_SOURCES]
  .filter((source) => only.size === 0 || only.has(source.id))
  .map((source) => ({ ...source, outputFile: `${source.id}.txt`, metadataFile: `${source.id}-source.json` }));
if (only.size > sources.length) throw new Error(`Unknown list id: ${[...only].filter((id) => !sources.some((source) => source.id === id)).join(", ")}.`);

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function readTextWithLimit(response, maximumBytes) {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    throw new Error(`Response declares ${declaredLength} bytes, above the ${maximumBytes}-byte limit.`);
  }
  const reader = response.body?.getReader();
  if (!reader) {
    const value = Buffer.from(await response.arrayBuffer());
    if (value.byteLength > maximumBytes) throw new Error(`Response exceeds ${maximumBytes} bytes.`);
    return value.toString("utf8");
  }

  const chunks = [];
  let received = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maximumBytes) {
        await reader.cancel("Velor response-size limit exceeded.").catch(() => undefined);
        throw new Error(`Response exceeds ${maximumBytes} bytes.`);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, received).toString("utf8");
}

// Downloads one approved HTTPS file; a redirect anywhere else is refused.
async function fetchText(url, label) {
  const approvedUrl = new URL(url);
  const response = await fetch(url, {
    headers: {
      "User-Agent": "Velor-Filter-Updater/0.4 (+reviewed local build tool)",
      "Accept": "text/plain"
    },
    signal: AbortSignal.timeout(60_000)
  });
  if (!response.ok) throw new Error(`${label} update failed with HTTP ${response.status}.`);
  const finalUrl = new URL(response.url);
  if (
    finalUrl.protocol !== "https:"
    || finalUrl.origin !== approvedUrl.origin
    || finalUrl.pathname !== approvedUrl.pathname
    || finalUrl.search !== approvedUrl.search
  ) {
    throw new Error(`${label} update redirected outside its approved HTTPS source.`);
  }
  return readTextWithLimit(response, MAX_PRIVACY_LIST_BYTES);
}

// Sub-lists a list pulls in with uBlock Origin's `!#include name.txt`, in the
// sections Velor keeps (applyListConditions), from the list's own directory.
// They are saved beside it as `<id>--<name>` and travel with it: if one
// fails, the list keeps its previous copy and previous sub-lists.
const INCLUDE_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]*\.txt$/;
async function fetchIncludes(definition, source) {
  const names = [...new Set(applyListConditions(source).split(/\r?\n/)
    .map((line) => /^!#include\s+(\S+)\s*$/.exec(line.trim())?.[1])
    .filter(Boolean))];
  const includes = [];
  for (const name of names) {
    if (!INCLUDE_NAME.test(name)) throw new Error(`${definition.id} includes ${name}, which is not a file in its own directory.`);
    const url = new URL(name, definition.url).href;
    const text = await fetchText(url, `${definition.id} sub-list ${name}`);
    const filters = privacyListFilterCount(text);
    if (filters === 0 || /^\s*</.test(text)) throw new Error(`${definition.id} sub-list ${name} is not a filter list.`);
    includes.push({ name, file: `${definition.id}--${name}`, source: url, sha256: sha256(text), filters, text });
  }
  return includes;
}

async function fetchSource(definition) {
  const metadataPath = resolve(dataDirectory, definition.metadataFile);
  const outputPath = resolve(dataDirectory, definition.outputFile);
  const previous = JSON.parse(await readFile(metadataPath, "utf8").catch(() => "null"));
  const approvedUrl = new URL(definition.url);
  if ((previous && previous.source !== definition.url) || approvedUrl.protocol !== "https:") {
    throw new Error(`${definition.id} metadata contains an unexpected source URL.`);
  }

  const source = await fetchText(definition.url, definition.id);
  const { filters, header } = validatePrivacyListText(source, definition, {
    previousFilters: Number(previous?.filters) || 0,
    allowJump: allowFeedJump
  });
  const parsed = extractConservativeAbpDomains(source);
  const includes = await fetchIncludes(definition, source);

  return {
    source,
    includes,
    outputPath,
    metadataPath,
    metadata: {
      source: definition.url,
      publisher: definition.publisher,
      title: definition.title || header.title || definition.metadataTitle,
      license: definition.license,
      licenseUrl: definition.licenseUrl,
      attributionUrl: definition.attributionUrl,
      fetchedAt: new Date().toISOString(),
      sha256: sha256(source),
      upstreamVersion: header.version,
      upstreamLastModified: header.lastModified,
      upstreamCommit: header.commit,
      filters,
      acceptedDomainRules: parsed.domains.length,
      exceptionDomains: parsed.exceptions.length,
      rejected: parsed.rejected,
      ...(includes.length ? { includes: includes.map(({ name, file, source: url, sha256: hash, filters: count }) => ({ name, file, source: url, sha256: hash, filters: count })) } : {})
    }
  };
}

// Each list is written atomically on its own; a failed list keeps its
// previous reviewed snapshot.
const results = await Promise.allSettled(sources.map(fetchSource));
let failures = 0;
for (const [index, result] of results.entries()) {
  if (result.status === "rejected") {
    failures += 1;
    const message = String(result.reason?.message || result.reason);
    const hint = message.includes("filter count changed") ? " Review it before rerunning with VELOR_ALLOW_FEED_JUMP=1." : "";
    console.error(`FAILED ${sources[index].id}: ${message} Kept the previous snapshot.${hint}`);
    continue;
  }
  const update = result.value;
  // The list and its sub-lists first, the metadata naming their hashes last;
  // sub-lists it no longer includes go.
  const files = [
    [update.outputPath, update.source],
    ...update.includes.map((include) => [resolve(dataDirectory, include.file), include.text]),
    [update.metadataPath, `${JSON.stringify(update.metadata, null, 2)}\n`]
  ];
  const temporaryPaths = files.map(([path]) => `${path}.tmp`);
  try {
    for (const [position, [, text]] of files.entries()) await writeFile(temporaryPaths[position], text);
    for (const [position, [path]] of files.entries()) await rename(temporaryPaths[position], path);
    const current = new Set(update.includes.map((include) => include.file));
    const prefix = `${sources[index].id}--`;
    for (const name of await readdir(dataDirectory)) {
      if (name.startsWith(prefix) && name.endsWith(".txt") && !current.has(name)) await unlink(resolve(dataDirectory, name));
    }
  } catch (error) {
    await Promise.all(temporaryPaths.map((path) => unlink(path).catch(() => undefined)));
    throw error;
  }
  console.log(
    `Updated ${update.metadata.title} ${update.metadata.upstreamVersion || update.metadata.upstreamLastModified} with `
    + `${update.metadata.filters} filters (${update.metadata.acceptedDomainRules} hostname candidates)`
    + `${update.includes.length ? ` and ${update.includes.length} sub-lists with ${update.includes.reduce((sum, include) => sum + include.filters, 0)} filters` : ""}.`
  );
}
// Exit 3: the run finished and only the failed lists kept their previous
// copy; refresh-lists.mjs does not download everything again for that.
if (failures > 0) process.exitCode = 3;
