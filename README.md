# Velor list sources

The list snapshots and build scripts behind the rule data in **Velor**, a
browser extension that blocks ads, trackers and dangerous sites.

Velor's packaged blocking rules, page-cleanup styles and page scripts are
compiled from the filter and threat lists in `filter-data/`, many of them
published under the GNU GPL version 3, and are distributed under GPL-3.0.
This repository is their source: the exact list texts each Velor version was
built from (with SHA-256 hashes in each `*-source.json`) and the scripts that
turn them into Velor's rules. Each Velor version is tagged here, starting
with `v0.7.0`.

## Rebuilding the rules

Needs Node.js 22; nothing to install. From this folder:

    node scripts/compile-rules.mjs

It writes `extension/rules/`, `extension/content/compiled-cosmetic.css`,
`extension/scriptlets/generated/` and `extension/lib/threat-ranges.js`. Apart
from the build time in `extension/rules/metadata.json`, they match the files
in the Velor package of the same version.

`node scripts/update-filter-data.mjs` downloads fresh copies of the ad and
annoyance lists, and `node scripts/update-threat-data.mjs` the threat lists,
with the same checks Velor's releases use.

## Licence

The scripts and other files here, apart from the lists in `filter-data/`, are
released under GPL-3.0 (see `LICENSE`). Each list in `filter-data/` keeps its
own licence, listed in `THIRD_PARTY_NOTICES.md`. Velor is not affiliated with
or endorsed by the list publishers.
