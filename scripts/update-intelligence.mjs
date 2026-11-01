import { createHash } from "node:crypto";
import { readFile, rename, unlink, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { THREAT_FEEDS, parseThreatFeed } from "../extension/lib/threat-policy.js";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataDirectory = resolve(projectRoot, "filter-data");
const allowFeedJump = process.env.VELOR_ALLOW_FEED_JUMP === "1";

// Every feed, including the optional gambling list, refreshes at build time
// with the same source, count and jump guardrails.
const feeds = THREAT_FEEDS.map((feed) => ({ ...feed, expectedSource: feed.url, outputFile: feed.file }));

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function readTextWithLimit(response, maximumBytes) {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    throw new Error(`Response declares ${declaredLength} bytes, above the ${maximumBytes}-byte limit.`);
  }
  if (!response.body?.getReader) {
    const value = Buffer.from(await response.arrayBuffer());
    if (value.byteLength > maximumBytes) throw new Error(`Response exceeds ${maximumBytes} bytes.`);
    return value.toString("utf8");
  }

  const reader = response.body.getReader();
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

async function fetchFeed(feed) {
  const metadataPath = resolve(dataDirectory, feed.metadataFile);
  const outputPath = resolve(dataDirectory, feed.outputFile);
  const metadata = JSON.parse(await readFile(metadataPath, "utf8"));
  if (metadata.source !== feed.expectedSource || new URL(metadata.source).protocol !== "https:") {
    throw new Error(`${feed.id} metadata contains an unexpected source URL.`);
  }
  const response = await fetch(feed.expectedSource, {
    headers: {
      "User-Agent": "Velor-Intelligence-Updater/0.3 (+reviewed local build tool)",
      "Accept": "text/plain"
    },
    signal: AbortSignal.timeout(60_000)
  });
  if (!response.ok) throw new Error(`${feed.id} update failed with HTTP ${response.status}.`);
  const finalUrl = new URL(response.url);
  const approvedUrl = new URL(feed.expectedSource);
  if (
    finalUrl.protocol !== "https:"
    || finalUrl.origin !== approvedUrl.origin
    || finalUrl.pathname !== approvedUrl.pathname
  ) {
    throw new Error(`${feed.id} update redirected outside its approved HTTPS source path.`);
  }

  const source = await readTextWithLimit(response, 50 * 1024 * 1024);
  const domains = parseThreatFeed(source, feed);
  if (domains.length < feed.minimumDomains || domains.length > feed.maximumDomains) {
    throw new Error(
      `${feed.id} update rejected: ${domains.length} domains is outside the expected `
      + `${feed.minimumDomains}–${feed.maximumDomains} range.`
    );
  }

  const previousCount = Number(metadata.domainCount) || 0;
  const lowerBound = Math.floor(previousCount * 0.4);
  const upperBound = Math.ceil(previousCount * 3);
  if (
    !allowFeedJump
    && previousCount > 0
    && (domains.length < lowerBound || domains.length > upperBound)
  ) {
    throw new Error(
      `${feed.id} update rejected: count changed from ${previousCount} to ${domains.length}. `
      + "Review the source and rerun with VELOR_ALLOW_FEED_JUMP=1 only if the change is legitimate."
    );
  }

  // ABP-format feeds carry their own `! Last modified:` header.
  const lastModified = source.match(/^! Last modified:\s*(.+?)\s*$/m)?.[1];
  return {
    id: feed.id,
    source,
    outputPath,
    metadataPath,
    metadata: {
      ...metadata,
      ...(lastModified ? { upstreamLastModified: lastModified } : {}),
      fetchedAt: new Date().toISOString(),
      sha256: sha256(source),
      domainCount: domains.length
    }
  };
}

async function writeFeed(update) {
  const temporarySourcePath = `${update.outputPath}.tmp`;
  const temporaryMetadataPath = `${update.metadataPath}.tmp`;
  try {
    await writeFile(temporarySourcePath, update.source);
    await writeFile(temporaryMetadataPath, `${JSON.stringify(update.metadata, null, 2)}\n`);
    await rename(temporarySourcePath, update.outputPath);
    await rename(temporaryMetadataPath, update.metadataPath);
  } catch (error) {
    await Promise.all([temporarySourcePath, temporaryMetadataPath].map((path) => unlink(path).catch(() => undefined)));
    throw error;
  }
}

// Feeds are independent: one retired or failing source must not freeze the others.
const results = await Promise.allSettled(feeds.map(async (feed) => {
  const update = await fetchFeed(feed);
  await writeFeed(update);
  return update;
}));

results.forEach((result, index) => {
  if (result.status === "fulfilled") {
    const update = result.value;
    console.log(
      `Updated ${update.id} with ${update.metadata.domainCount} domains `
      + `(${update.metadata.sha256.slice(0, 12)}…).`
    );
  } else {
    console.error(`FAILED ${feeds[index].id}: ${result.reason?.message || result.reason}. Kept the previous snapshot.`);
    // Exit 3: finished, only the failed feeds kept their previous copy.
    process.exitCode = 3;
  }
});
