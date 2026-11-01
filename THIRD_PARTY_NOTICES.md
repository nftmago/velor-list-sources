# Third-party notices

## Ad and tracker lists

Velor includes generated data derived from these filter lists:

- [EasyList and EasyPrivacy](https://easylist.to/), copyright the EasyList authors, published under either [GNU GPL version 3 or later or Creative Commons Attribution-ShareAlike 3.0 or later](https://easylist.to/pages/licence.html). Velor uses them under GPL version 3 or later.
- [AdGuard Base filter](https://github.com/AdguardTeam/AdguardFilters), copyright AdGuard, [GPL-3.0](https://github.com/AdguardTeam/AdguardFilters/blob/master/LICENSE).
- [uBlock filters, uBlock filters – Privacy, uBlock filters – Unbreak and uBlock filters – Quick fixes](https://github.com/uBlockOrigin/uAssets), copyright Raymond Hill and the uAssets contributors, [GPL-3.0](https://github.com/uBlockOrigin/uAssets/blob/master/LICENSE), including the sub-lists uBlock filters and Privacy pull in with `!#include` (the general, 2020–2026 and link-shortener files and `resource-abuse.txt`).
- The optional annoyance lists: [EasyList – Cookie Notices, Newsletter Notices, Notifications, Social Widgets, Chat Widgets, Anti AI Suggestions and Annoyances](https://easylist.to/), copyright the EasyList authors, under the EasyList licence above (GPL version 3 or later used); [AdGuard Popups, Widgets, Other Annoyances and Mobile App Banners filters](https://github.com/AdguardTeam/AdguardFilters), copyright AdGuard, [GPL-3.0](https://github.com/AdguardTeam/AdguardFilters/blob/master/LICENSE).
- The optional regional lists, each shipped as compiled data under the licence below and listed with its source in `FILTER_SOURCES.md`; the sub-lists the Czech and Slovak, Finnish, Hebrew, Romanian and Thai lists pull in with `!#include` come from the same projects under the same licences:
  - AdGuard Chinese, Dutch, French, Japanese, Russian, Spanish/Portuguese, Turkish and Ukrainian filters, copyright AdGuard, [GPL-3.0](https://github.com/AdguardTeam/AdguardFilters/blob/master/LICENSE).
  - EasyList Germany, EasyList Hebrew, EasyList Italy, EasyList Spanish and IndianList, copyright the EasyList authors, under the [EasyList licence](https://easylist.to/pages/licence.html) (GPL version 3 or later used).
  - [ABPindo](https://github.com/ABPindo/indonesianadblockrules), copyright the ABPindo authors, GPL version 3 or later (dual-licensed with CC BY-SA 3.0).
  - [filterslists-KO](https://github.com/FilteringDev/filterslists-KO), FilteringDev, [GPL-3.0](https://github.com/FilteringDev/filterslists-KO/blob/master/LICENSE); [EasyList Lithuania](https://github.com/EasyList-Lithuania/easylist_lithuania), GPL-3.0; [Frellwit's Swedish Filter](https://github.com/lassekongo83/Frellwits-filter-lists), GPL-3.0; [ABPVN](https://github.com/abpvn/abpvn), GPL-3.0.
  - [Easylist Czech and Slovak filter list](https://github.com/tomasko126/easylistczechandslovak) by tomasko126 and the adblock.sk contributors, [Greek AdBlock Filter](https://github.com/kargig/greek-adblockplus-filter) by kargig, and [Latvian List](https://github.com/Latvian-List/adblock-latvian) by its contributors, each under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/), whose adaptations may be licensed under GPL-3.0.
  - [Hufilter](https://github.com/hufilter/hufilter) by the Hufilter contributors, [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
  - [Liste AR](https://code.google.com/archive/p/liste-ar-adblock/) by the Liste AR authors, [CC BY-SA 3.0](https://creativecommons.org/licenses/by-sa/3.0/). CC BY-SA 3.0 lets an adaptation be licensed under a later version of the same licence, and CC BY-SA 4.0 adaptations may be licensed under GPL-3.0; Velor relies on that path to ship its compiled copy beside GPL-3.0 data. This is Velor's reading of the two licences, not a statement by the list's authors.
  - [EasyList Thailand](https://github.com/easylist-thailand/easylist-thailand), [Apache-2.0](https://github.com/easylist-thailand/easylist-thailand/blob/master/LICENSE); [Macedonian adBlock Filters](https://github.com/DeepSpaceHarbor/Macedonian-adBlock-Filters) by DeepSpaceHarbor and [ROad Block](https://github.com/tcptomato/ROad-Block) by tcptomato, each [MIT](https://opensource.org/license/mit).
  - Brave's [Icelandic list](https://github.com/brave/adblock-lists) (forked from adblock.gardar.net), [MPL-2.0](https://github.com/brave/adblock-lists/blob/master/LICENSE); its compiled copy is the MPL-covered file `extension/rules/regional/icelandic.json` with its sections of the regional buckets, and the source is linked here.
  - The Albanian ([AnXh3L0](https://github.com/anxh3l0/blocklist)), Finnish ([finnish-easylist-addition](https://github.com/finnish-easylist-addition/finnish-easylist-addition)) and Slovenian ([betterwebleon](https://github.com/betterwebleon/slovenian-list)) lists under the [Unlicense](https://unlicense.org/), and the Estonian list ([sander85](https://github.com/sander85/uBO-et)) under [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).
- [Peter Lowe's ad and tracking server list](https://pgl.yoyo.org/adservers/), by Peter Lowe, who invites combining it with other lists and republishing it, with credit.

Because GPL-3.0 inputs are combined, Velor distributes the generated `extension/rules/expanded-privacy.json`, `extension/rules/semantic-privacy.json`, `extension/rules/privacy-exceptions.json`, `extension/rules/popup-hosts.json`, `extension/content/compiled-cosmetic.css`, `extension/rules/cosmetic/`, `extension/rules/annoyances/`, `extension/rules/regional/` and `extension/scriptlets/generated/` derivatives under **GPL-3.0** (the Icelandic list's compiled data keeps MPL-2.0, as above). Releases up to 0.6 contained only EasyList and EasyPrivacy data and distributed it under CC BY-SA 3.0.

Velor modifies the source material by:

- accepting exact `||hostname^` anchors with no options other than `third-party`/`3p` and `important`, plus host-anchored paths and specific unanchored URL patterns with supported resource types, party constraints, initiator scopes and match case;
- applying every compiled block only to subresources, never main-frame navigation, and keeping unanchored patterns off YouTube's own player hosts;
- compiling network exceptions into allow rules that outrank ordinary blocks but not `important` ones; exceptions that cannot be represented exactly, and `badfilter`, remove the related hostname blocks instead;
- serving Velor's own stand-in resources for `redirect` filters whose resource Velor implements, and dropping the others;
- collecting exact `$popup` hosts for Velor's pop-up defense;
- excluding invalid/reserved/IP hosts, selected multipurpose infrastructure roots, duplicates and starter-corpus overlaps, crediting a rule shared by several lists to the first list above, and packing hostnames into large Chromium Declarative Net Request rules;
- accepting standard-CSS hide selectors and hostname-scoped exceptions, suppressing exception-bearing generic selectors, and sharding site selectors into deterministic buckets; and
- running page-script (scriptlet) filters only through Velor's own packaged implementations of 54 scriptlet types, accepting `trusted-*` ones only from uBlock Origin's and AdGuard's own lists, never on YouTube's own hosts, and dropping filters for any other scriptlet; and
- rejecting regular-expression network filters, procedural/extended cosmetics, CSP/header changes and other unsupported options instead of approximating them.

Exact versions, commits, retrieval times, SHA-256 values, compiled counts and policy flags are in `filter-data/*-source.json` and `extension/rules/metadata.json`.

The list snapshots and the scripts that compile them are published, tagged with each Velor version, at [github.com/nftmago/velor-list-sources](https://github.com/nftmago/velor-list-sources) under GPL-3.0 (each list keeps its own licence).

## URLhaus

Malware host data is published by [abuse.ch URLhaus](https://urlhaus.abuse.ch/) under [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/). Velor retrieves it through the [malware-filter project's urlhaus-filter mirror](https://gitlab.com/malware-filter/urlhaus-filter) (CC0 1.0 / MIT).

## CERT Polska Warning List

Phishing/fraud domains are published by [CERT Polska / NASK PIB](https://cert.pl/lista-ostrzezen/). Its public API specification permits unrestricted manual and automated processing. Exact retrieval metadata and hashes are recorded with the snapshot.

## HaGeZi Threat Intelligence mini, Fake and Gambling mini

Copyright HaGeZi and contributors, [dns-blocklists](https://github.com/hagezi/dns-blocklists), [GPL-3.0](https://github.com/hagezi/dns-blocklists/blob/main/LICENSE). Sources are `wildcard/tif.mini-onlydomains.txt`, `wildcard/fake-onlydomains.txt` and, for the optional gambling list, `wildcard/gambling.mini-onlydomains.txt` from that repository. Velor packages parsed snapshots and distributes the corresponding rule derivatives under GPL-3.0: the threat lists in `extension/rules/threats.json` and the gambling list in its own `extension/rules/gambling.json`, which ships disabled and is used only when the user turns **Block gambling sites** on.

## uBlock Origin uAssets — Badware risks

Copyright Raymond Hill and contributors, [uBlock Origin uAssets](https://github.com/uBlockOrigin/uAssets), [GPL-3.0](https://github.com/uBlockOrigin/uAssets/blob/master/LICENSE). Source: `https://ublockorigin.github.io/uAssets/filters/badware.txt` ("uBlock₀ filters – Badware risks"). Velor reads only whole-host document blocks (`||hostname^` with no options or only `doc`/`document`/`all`/`important`/`reason=`), honours every `@@||hostname` exception for the host and its subdomains, and ignores the list's paths, wildcards, regexes, resource-type and scope options, cosmetic filters and scriptlets. The parsed snapshot and its rule derivative within `extension/rules/threats.json` are distributed under GPL-3.0.

## malware-filter phishing-filter

Copyright the [malware-filter project](https://gitlab.com/malware-filter/phishing-filter) and its contributors; incorporates OpenPhish, PhishTank and IPThreat. Source: `https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt`. The snapshot and corresponding rule derivative are licensed [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).

For all threat sources, Velor normalizes hostnames, excludes invalid and protected shared domains, deduplicates in fixed source priority, removes redundant descendants and groups domains into DNR blocks. Per-source attribution, timestamps, hashes and ID ranges identify each derivative within `rules/threats.json`; parsed original snapshots live in `rules/threat-feeds/`. These modifications do not imply publisher endorsement.

## AdGuard URL Tracking

Copyright AdGuard Software Ltd and contributors, [AdGuardFilters](https://github.com/AdguardTeam/AdguardFilters), [GPL-3.0](https://github.com/AdguardTeam/AdguardFilters/blob/master/LICENSE). Source: `https://filters.adtidy.org/extension/chromium/filters/17.txt`. Velor's `rules/url-cleaning.json` includes a GPL-3.0 derivative: literal named removal rules only, narrowed to frame navigations and exact hosts/literal paths, conservative exceptions, grouped parameters, and no regex or remove-all directives. The original 24-parameter Velor policy is also retained. Source version, hash and compilation counts appear in `rules/metadata.json`.

## Offline ML research sources (not packaged in the extension)

Velor's private research workspace can import the following datasets. Raw rows,
HTML, DNS results, IP addresses, and trained checkpoints are excluded from the
browser-extension package and Git repository.

- **PhreshPhish v1.0.1**, Thomas Dalton et al., is released under CC BY 4.0 for
  anti-phishing research. Velor imports only URL, label, date, upstream split,
  and a pinned revision; it does not import the HTML field.
- **DeepURLBench**, Deep Instinct Research Team, is released under CC BY-NC 4.0.
  It is used only for the owner's private, non-commercial Velor research. Any
  checkpoint trained with it remains private/non-commercial and separate from
  the permissive recipe. Velor excludes DNS, TTL, and IP-address columns.
- **Qwen3.5-2B**, Qwen Team, is licensed Apache-2.0. The offline teacher uses a
  pinned official Hugging Face revision with remote model code disabled.

Dataset URLs are hostile text samples. Velor's importer never resolves, visits,
or executes them.

## tldts

Velor packages **tldts 7.4.9** as `extension/lib/vendor/tldts.js`, copyright
(c) 2017 Thomas Parisot, 2018 Rémi Berson,
[MIT](https://github.com/remusao/tldts/blob/master/LICENSE); the vendored file
carries the full licence text and is regenerated by `scripts/vendor-tldts.mjs`.
The list compiler uses its bundled Public Suffix List snapshot to reject
exceptions that name a bare public suffix, and dataset construction uses it to
derive registrable-domain families, including private suffixes, so related
subdomains stay together and no family leaks across ML splits.
