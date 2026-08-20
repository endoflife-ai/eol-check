# eol-check — fail CI when your stack runs end-of-life software

A zero-dependency GitHub Action that scans your repo for runtime versions
(`.nvmrc`, `.python-version`, `.ruby-version`, `go.mod`, `package.json`
engines, `Dockerfile` base images) and checks each one against
[endoflife.ai](https://endoflife.ai). Anything past end of life fails the
build with a file-anchored annotation; anything close gets a warning and a
date. No API key, no configuration required.

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

Anything else — databases, OSes, appliances, 500+ products — via the
`products` input as `slug:version` pairs. Slugs are the path segments on
endoflife.ai (e.g. [`endoflife.ai/postgresql`](https://endoflife.ai/postgresql) → `postgresql`).

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `products` | `''` | Extra `slug:version` pairs, comma-separated |
| `scan` | `true` | Auto-detect from repo files |
| `fail-on` | `eol` | `eol` \| `approaching` \| `never` |
| `warn-days` | `90` | Warn when EOL is within this many days |

## Outputs

`eol-count`, `approaching-count`, `checked-count`, and `report` (the
markdown table also written to the job summary).

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
dates for 500+ products, verified against vendor sources daily, with
[EOL Risk Scores](https://endoflife.ai/risk-score) and a
[free API](https://endoflife.ai/api). Underlying community dates from
[endoflife.date](https://endoflife.date) (MIT).

## License

MIT
