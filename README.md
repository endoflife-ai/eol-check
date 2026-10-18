# eol-check — fail CI when your stack runs end-of-life software

A zero-dependency GitHub Action that scans your repo for runtime versions
(`.nvmrc`, `.python-version`, `.ruby-version`, `go.mod`, `package.json`
engines, `Dockerfile` base images) — or reads your SBOM — and checks each
one against [endoflife.ai](https://endoflife.ai). Anything past end of life fails the
build with a file-anchored annotation; anything close gets a warning and a
date. No API key, no configuration required: checks resolve from endoflife.ai's public
scanner database, and an optional `api-key` input switches repo checks to the live API.

```yaml
- uses: endoflife-ai/eol-check@v1
```

That's the whole integration. A fuller example:

```yaml
name: EOL gate
on:
  pull_request:
  schedule:
    - cron: '0 6 * * 1'   # weekly — EOL dates pass whether or not you push code

jobs:
  eol:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: endoflife-ai/eol-check@v1
        with:
          products: 'postgresql:14, kubernetes:1.32'   # things not visible in the repo
          fail-on: 'eol'                                # or 'approaching' / 'never'
          warn-days: '90'
```

## What it detects automatically

| Source | Product |
|---|---|
| `.nvmrc`, `.node-version`, `package.json` `engines.node` | Node.js |
| `.python-version` | Python |
| `.ruby-version` | Ruby |
| `go.mod` (`go 1.x`) | Go |
| `Dockerfile*` `FROM` images (root + 2 levels) | node, python, ruby, golang, php, nginx, postgres, mysql, mariadb, redis, mongo, alpine, debian, ubuntu |

Anything else — databases, OSes, appliances, 600+ products — via the
`products` input as `slug:version` pairs. Slugs are the path segments on
endoflife.ai (e.g. [`endoflife.ai/postgresql`](https://endoflife.ai/postgresql) → `postgresql`).

## SBOM mode

Point the action at a CycloneDX or SPDX JSON SBOM and every component is
checked — libraries, base images, runtimes — not just what the repo scan can
see. Components are resolved by **package URL** (purl), the identifier SBOM
generators emit, against [endoflife.ai/purl-map.json](https://endoflife.ai/purl-map.json):
an exact match or no match, never a guess from the name. Components
endoflife.ai does not track are counted in the summary and get no verdict.

```yaml
- uses: anchore/sbom-action@v0          # or Trivy, cdxgen, your build's own SBOM
  with:
    format: cyclonedx-json
    output-file: sbom.cdx.json
- uses: endoflife-ai/eol-check@v1
  with:
    sbom: sbom.cdx.json                  # comma-separate several files
```

SBOM mode makes **no API calls**: it downloads endoflife.ai's scanner
database once (the same file the site's Stack Scanner uses, rebuilt at every
site build, at least daily) and resolves locally, so a 3,000-component SBOM
costs the same as a 3-component one and never hits a rate limit. Versions
resolve to the tracked release line (exact cycle, else major.minor, else
major — never a prefix match, never a newest-cycle fallback).

### Enriched SBOM out

Add `sbom-output` and the action writes your document back with the verdict on
every component — CycloneDX `properties` (or SPDX annotations) in the
`endoflife:` namespace: `status`, `product`, `cycle`, `eol_date`,
`days_until_eol` / `days_past_eol`, `purl_matched`, `matched_by`, `score_url`,
and `status=not-tracked` with a reason where we have no verdict; plus a
document-level summary (counts, unique products, the `gate` verdict) and a
`metadata.tools` entry. Serial numbers, bom-refs, hashes and licenses are
untouched. It is the same schema the API's
[`POST /v1/sbom?enrich=1`](https://endoflife.ai/sbom-enrichment.json) produces,
minus risk scores, so the file drops straight into Dependency-Track or a
release's assets.

```yaml
- uses: endoflife-ai/eol-check@v1
  with:
    sbom: sbom.cdx.json
    sbom-output: sbom.enriched.cdx.json
- uses: actions/upload-artifact@v4
  with:
    name: sbom-enriched
    path: sbom.enriched.cdx.json
```

| Product | Status | EOL date | Found in |
|---|---|---|---|
| nodejs 16 | 🔴 EOL | 2023-09-11 | sbom.cdx.json · pkg:docker/library/node@16.20.2 |
| postgresql 14 | 🟡 EOL in 68d | 2026-11-12 | sbom.cdx.json · pkg:docker/library/postgres@14.13 |
| log4j 2 | 🟢 supported | — | sbom.cdx.json · pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1 |

> **notice** · 2 SBOM components not tracked by endoflife.ai — no verdict, never a guess (e.g. pkg:npm/left-pad@1.3.0).

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `products` | `''` | Extra `slug:version` pairs, comma-separated |
| `scan` | `true` | Auto-detect from repo files |
| `sbom` | `''` | CycloneDX / SPDX JSON file(s), comma-separated — see SBOM mode |
| `sbom-output` | `''` | Write the enriched SBOM(s) here — a file, or a directory with a trailing slash |
| `fail-on` | `eol` | `eol` \| `approaching` \| `never` |
| `warn-days` | `90` | Warn when EOL is within this many days |
| `api-key` | `''` | Optional endoflife.ai API key, from a secret. With it, repo and `products` checks query the live API; without it they resolve locally (see below) |

## API key (optional)

Keyless calls to api.endoflife.ai end on 2026-11-16. This Action does not need
a key: without one, repo-scan and `products` checks resolve from the public
[scanner database](https://endoflife.ai/scanner-db.json), the same data and
matching rules as SBOM mode, with no rate limit. To query the live API instead,
add a key (free keys at [endoflife.ai/api](https://endoflife.ai/api#free-key)):

```yaml
- uses: endoflife-ai/eol-check@v1
  with:
    api-key: ${{ secrets.ENDOFLIFE_API_KEY }}
```

If the API rejects the key or rate-limits it, the Action falls back to the
scanner database and says so in a notice; the job does not fail for that.

## Outputs

`eol-count`, `approaching-count`, `checked-count`, `sbom-components`,
`unmatched-count`, and `report` (the markdown table also written to the job
summary).

## Example output

> **error** · nodejs 18 is END OF LIFE since 2025-04-30 (477 days ago) — no more security fixes. https://endoflife.ai/score/nodejs/18
> **warning** · python 3.10 reaches end of life in 72 days (2026-10-31). Plan the upgrade.

Plus a job-summary table:

| Product | Status | EOL date | Found in |
|---|---|---|---|
| nodejs 18 | 🔴 EOL | 2025-04-30 | .nvmrc |
| python 3.10 | 🟡 EOL in 72d | 2026-10-31 | Dockerfile |
| go 1.24 | 🟢 supported | 2026-08-12 | go.mod |

## README badge

Show a live EOL status badge for any version you ship against:

```markdown
![Node 22 EOL status](https://api.endoflife.ai/v1/badge/nodejs/22)
```

## Data

Lifecycle data comes from [endoflife.ai](https://endoflife.ai) — end-of-life
dates for 600+ products, each labelled with its source on the site, with
[EOL Risk Scores](https://endoflife.ai/risk-score) and an
[API](https://endoflife.ai/api) (free key, 150 requests a day). Underlying community dates from
[endoflife.date](https://endoflife.date) (MIT).

## License

MIT
