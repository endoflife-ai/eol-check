// eol-check — fail CI when the stack runs end-of-life software.
// Zero dependencies; Node 20+. Data: endoflife.ai.
//
// Without an API key every check resolves locally against the public
// scanner-db.json (one download, no rate limit, no key): keyless calls to
// api.endoflife.ai end on 2026-11-16, and this keeps every existing workflow
// working unchanged. With the optional `api-key` input the repo-scan and
// `products` checks call the live API instead (X-API-Key header); a 401, 403 or
// 429 from the API falls back to the local database with a notice.
'use strict';
const fs = require('fs');
const path = require('path');

const API = 'https://api.endoflife.ai/v1/status';
// SBOM mode resolves against the same static database the endoflife.ai Stack
// Scanner uses (regenerated at every site build, checked by its cross-surface
// gate) — one download, no per-component API calls, no rate limit, so a
// 3,000-component SBOM costs the same as a 3-component one.
const SCANNER_DB = 'https://endoflife.ai/scanner-db.json';
const UA = 'eol-check-action/1.3 (+https://github.com/endoflife-ai/eol-check)';
const ACTION_VERSION = '1.3.0';

const input = (name, dflt) => {
  const v = process.env['INPUT_' + name.replace(/ /g, '_').toUpperCase()];
  return v === undefined || v === '' ? dflt : v;
};
const esc = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const annotate = (level, msg, file) =>
  console.log(`::${level}${file ? ` file=${esc(file)}` : ''}::${esc(msg)}`);

// How each product's detected version maps to an endoflife.ai cycle.
const CYCLE_STYLE = {
  nodejs: 'major', postgresql: 'major', debian: 'major', mongodb: 'major.minor',
  python: 'major.minor', ruby: 'major.minor', go: 'major.minor', php: 'major.minor',
  mysql: 'major.minor', mariadb: 'major.minor', nginx: 'major.minor', redis: 'major.minor',
  ubuntu: 'major.minor', 'alpine-linux': 'major.minor',
};
const IMAGE_SLUGS = {
  node: 'nodejs', python: 'python', ruby: 'ruby', golang: 'go', php: 'php',
  nginx: 'nginx', postgres: 'postgresql', mysql: 'mysql', mariadb: 'mariadb',
  redis: 'redis', mongo: 'mongodb', alpine: 'alpine-linux', debian: 'debian', ubuntu: 'ubuntu',
};

function toCycle(slug, raw) {
  const m = String(raw).trim().replace(/^v/i, '').match(/^(\d+)(?:\.(\d+))?/);
  if (!m) return null;
  const style = CYCLE_STYLE[slug] || 'major.minor';
  if (style === 'major') return m[1];
  return m[2] !== undefined ? `${m[1]}.${m[2]}` : m[1];
}

function detect(root) {
  const found = []; // {slug, version, file}
  const add = (slug, raw, file) => {
    const version = toCycle(slug, raw);
    if (version) found.push({ slug, version, file });
  };
  const read = (f) => { try { return fs.readFileSync(path.join(root, f), 'utf8'); } catch { return null; } };

  for (const f of ['.nvmrc', '.node-version']) {
    const t = read(f);
    if (t && /\d/.test(t)) { add('nodejs', t.trim(), f); break; }
  }
  const py = read('.python-version');
  if (py && /\d/.test(py)) add('python', py.trim().split(/\s+/)[0], '.python-version');
  const rb = read('.ruby-version');
  if (rb && /\d/.test(rb)) add('ruby', rb.trim(), '.ruby-version');
  const gomod = read('go.mod');
  if (gomod) { const m = gomod.match(/^go\s+(\d+\.\d+)/m); if (m) add('go', m[1], 'go.mod'); }
  const pkg = read('package.json');
  if (pkg && !found.some((x) => x.slug === 'nodejs')) {
    try {
      const eng = (JSON.parse(pkg).engines || {}).node || '';
      const m = String(eng).match(/(\d+)(?:\.(\d+))?/);
      if (m) add('nodejs', m[0], 'package.json');
    } catch {}
  }
  // Dockerfiles: root + one level of subdirectories (skip heavy/irrelevant dirs).
  const dockerfiles = [];
  const skip = new Set(['node_modules', '.git', 'vendor', 'dist', 'build', '.next', 'target']);
  const scanDir = (dir, depth) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.isFile() && /^Dockerfile([._-].+)?$/i.test(e.name)) dockerfiles.push(path.join(dir, e.name));
      else if (e.isDirectory() && depth > 0 && !skip.has(e.name) && !e.name.startsWith('.')) scanDir(path.join(dir, e.name), depth - 1);
    }
  };
  scanDir(root, 2);
  for (const df of dockerfiles) {
    let t; try { t = fs.readFileSync(df, 'utf8'); } catch { continue; }
    const rel = path.relative(root, df);
    for (const line of t.split('\n')) {
      const m = line.match(/^\s*FROM\s+(?:--platform=\S+\s+)?([a-z0-9._\/-]+):([A-Za-z0-9._-]+)/i);
      if (!m) continue;
      const image = m[1].split('/').pop();
      const slug = IMAGE_SLUGS[image];
      if (!slug) continue;
      if (/^(latest|stable|current|lts)$/i.test(m[2])) continue;
      add(slug, m[2], rel);
    }
  }
  // dedupe by slug:version
  const seen = new Set();
  return found.filter((x) => { const k = x.slug + ':' + x.version; if (seen.has(k)) return false; seen.add(k); return true; });
}

// Live API check (only with an api-key). Returns {fallback: true} on 401/403/429 so
// the caller can resolve the item locally instead of failing the job.
async function check(item, apiKey) {
  const url = `${API}/${encodeURIComponent(item.slug)}/${encodeURIComponent(item.version)}`;
  try {
    const res = await fetch(url, { headers: { 'User-Agent': UA, 'X-API-Key': apiKey } });
    if (res.status === 404) return { ...item, unknown: true };
    if (res.status === 401 || res.status === 403 || res.status === 429) return { ...item, fallback: true, status: res.status };
    if (!res.ok) return { ...item, error: `HTTP ${res.status}` };
    return { ...item, ...(await res.json()) };
  } catch (e) {
    return { ...item, error: String(e && e.message || e) };
  }
}

// Local check against scanner-db.json: the same cycle matcher and status rules as
// SBOM mode (and the endoflife.ai Stack Scanner), so both modes give one verdict.
function checkLocal(item, products) {
  const p = products[item.slug];
  if (!p) return { ...item, unknown: true };
  const cycle = findBestCycle(p.cycles, item.version);
  if (!cycle) return { ...item, unknown: true };
  const dated = typeof cycle.eol === 'string' && /^\d{4}-\d{2}-\d{2}/.test(cycle.eol);
  const days = dated ? daysUntil(cycle.eol.slice(0, 10)) : null;
  const isEol = cycle.s === 'eol' || (days != null && days < 0);
  return {
    ...item, version: String(cycle.c),
    is_eol: isEol,
    eol_date: dated ? cycle.eol.slice(0, 10) : null,
    eol_unpublished: cycle.eol === true,
    days_past_eol: isEol && days != null ? -days : null,
    days_until_eol: !isEol && days != null ? days : null,
    score_url: `https://endoflife.ai/score/${item.slug}/${cycle.c}`,
  };
}

// ── SBOM mode ────────────────────────────────────────────────────────────────
// A CycloneDX or SPDX JSON document names components by package URL (purl).
// Resolution is purl-first and exact: a component with a purl matches only if
// endoflife.ai publishes that purl for a product (endoflife.ai/purl-map.json);
// it is never guessed from the name. Components without a purl match by name
// only when the name is exactly a tracked product's slug, display name or a
// well-known image name. Everything else is reported as "not tracked" — a
// count, never a verdict. The normaliser, cycle matcher and status rules are
// the ones the Stack Scanner runs (endoflife.ai/scanner.js), kept identical.

function normalisePurl(p) {
  const s = String(p || '').trim();
  const m = /^pkg:([A-Za-z0-9.+-]+)\/(.+)$/.exec(s);
  if (!m) return null;
  let rest = m[2];
  const hash = rest.indexOf('#'); if (hash >= 0) rest = rest.slice(0, hash);
  const q = rest.indexOf('?'); if (q >= 0) rest = rest.slice(0, q);
  const at = rest.lastIndexOf('@');
  if (at > 0 && rest[at - 1] !== '/') rest = rest.slice(0, at);
  if (!rest || /^[/@]*$/.test(rest)) return null;
  const type = m[1].toLowerCase();
  let name = rest.replace(/%40/gi, '@');
  if (type === 'pypi') name = name.replace(/_/g, '-');
  return `pkg:${type}/${name}`.toLowerCase();
}
function purlVersion(p) {
  const s = String(p || '').trim();
  const m = /^pkg:[A-Za-z0-9.+-]+\/(.+)$/.exec(s);
  if (!m) return null;
  let rest = m[1];
  const hash = rest.indexOf('#'); if (hash >= 0) rest = rest.slice(0, hash);
  const q = rest.indexOf('?'); if (q >= 0) rest = rest.slice(0, q);
  const at = rest.lastIndexOf('@');
  if (at > 0 && rest[at - 1] !== '/') return decodeURIComponent(rest.slice(at + 1)) || null;
  return null;
}

function parseSbom(doc) {
  const comps = []; // {name, version, purl}
  if (!doc || typeof doc !== 'object') return { error: 'not a JSON object' };
  if (doc.bomFormat === 'CycloneDX' || Array.isArray(doc.components)) {
    const walk = (list) => {
      for (const c of list || []) {
        if (!c || typeof c !== 'object') continue;
        comps.push({ name: c.name || '', version: c.version || '', purl: c.purl || '', ref: c });
        if (Array.isArray(c.components)) walk(c.components);
      }
    };
    if (doc.metadata && doc.metadata.component) walk([doc.metadata.component]);
    walk(doc.components);
    return { format: 'CycloneDX', components: comps };
  }
  if (doc.spdxVersion || Array.isArray(doc.packages)) {
    for (const p of doc.packages || []) {
      if (!p || typeof p !== 'object') continue;
      const ref = (p.externalRefs || []).find((r) => r && r.referenceType === 'purl' && r.referenceLocator);
      comps.push({ name: p.name || '', version: p.versionInfo || '', purl: ref ? ref.referenceLocator : '', ref: p });
    }
    return { format: 'SPDX', components: comps };
  }
  return { error: 'not a CycloneDX or SPDX JSON document (no bomFormat/components or spdxVersion/packages)' };
}

// Exact cycle, else exact major.minor, else the bare major. No prefix
// matching ("2.28" must never match "2.3") and no newest-cycle fallback.
function findBestCycle(cycles, requestedVersion) {
  if (!Array.isArray(cycles) || cycles.length === 0 || !requestedVersion) return null;
  const v = String(requestedVersion).replace(/^v/i, '');
  const parts = v.split('.');
  const exact = cycles.find((c) => String(c.c) === v);
  if (exact) return exact;
  if (parts.length >= 2) {
    const mm = parts[0] + '.' + parts[1];
    const hit = cycles.find((c) => String(c.c) === mm);
    if (hit) return hit;
  }
  return cycles.find((c) => String(c.c) === parts[0]) || null;
}

function daysUntil(dateStr) {
  const t = Date.parse(dateStr + 'T00:00:00Z');
  if (Number.isNaN(t)) return null;
  const today = new Date(); today.setUTCHours(0, 0, 0, 0);
  return Math.round((t - today.getTime()) / 86400000);
}

async function loadScannerDb() {
  const res = await fetch(SCANNER_DB, { headers: { 'User-Agent': UA } });
  if (!res.ok) throw new Error(`scanner-db.json HTTP ${res.status}`);
  const db = await res.json();
  if (!db || !db.products || typeof db.products !== 'object') throw new Error('scanner-db.json: unexpected shape');
  loadScannerDb.generated = typeof db.generated === 'string' ? db.generated.slice(0, 10) : undefined;
  return db.products;
}

function buildNameLookup(products) {
  const byName = {};
  for (const slug in products) {
    byName[slug.toLowerCase()] = slug;
    const n = products[slug] && products[slug].name;
    if (n) byName[String(n).toLowerCase()] = slug;
  }
  for (const img in IMAGE_SLUGS) if (products[IMAGE_SLUGS[img]]) byName[img] = IMAGE_SLUGS[img];
  return byName;
}
function buildPurlLookup(products) {
  const lookup = {};
  for (const slug in products) for (const p of (products[slug] && products[slug].purl) || []) { const k = normalisePurl(p); if (k) lookup[k] = slug; }
  return lookup;
}

// Returns {results: [...status-shaped rows], unmatched: [labels], components}
function checkSbomFile(file, text, products, purlLookup, nameLookup) {
  let doc;
  try { doc = JSON.parse(text); } catch (e) { return { error: `not valid JSON (${e.message})` }; }
  const parsed = parseSbom(doc);
  if (parsed.error) return { error: parsed.error };
  const results = [], unmatched = [], seen = new Set();
  const annotations = []; // one per parsed component, same schema as the API's enrich mode
  const pt = (purl) => { const m = /^pkg:([A-Za-z0-9.+-]+)\//.exec(String(purl || '')); return m ? m[1].toLowerCase() : undefined; };
  for (const c of parsed.components) {
    let slug = null, how = null;
    if (c.purl) { const k = normalisePurl(c.purl); slug = k && purlLookup[k] ? purlLookup[k] : null; how = 'purl'; }
    else if (c.name) { slug = nameLookup[String(c.name).toLowerCase()] || null; how = 'name'; }
    const label = c.purl || (c.name ? c.name + (c.version ? '@' + c.version : '') : '(unnamed component)');
    const purlMatched = c.purl ? normalisePurl(c.purl) || undefined : undefined;
    if (!slug) { unmatched.push(label); annotations.push({ status: 'not-tracked', reason: c.purl ? 'purl not tracked' : 'name not recognised' }); continue; }
    const version = (c.purl && purlVersion(c.purl)) || c.version || '';
    const cycle = findBestCycle(products[slug].cycles, version);
    if (!cycle) { unmatched.push(`${label} (version not tracked)`); annotations.push({ status: 'version-not-tracked', product: slug, product_url: `https://endoflife.ai/${slug}`, matched_by: how, purl_matched: purlMatched, purl_type: pt(c.purl), reason: version ? 'Version not tracked' : 'No version in SBOM' }); continue; }
    // Status is what the build published (cycle.s), never re-derived from the
    // eol boolean; a dated cycle also gets day counts from its date.
    const dated = typeof cycle.eol === 'string' && /^\d{4}-\d{2}-\d{2}/.test(cycle.eol);
    const days = dated ? daysUntil(cycle.eol.slice(0, 10)) : null;
    const isEol = cycle.s === 'eol' || (days != null && days < 0);
    const row = {
      slug, version: String(cycle.c), file, component: label, matched_by: how,
      is_eol: isEol,
      eol_date: dated ? cycle.eol.slice(0, 10) : null,
      eol_unpublished: cycle.eol === true,
      days_past_eol: isEol && days != null ? -days : null,
      days_until_eol: !isEol && days != null ? days : null,
      score_url: `https://endoflife.ai/score/${slug}/${cycle.c}`,
    };
    annotations.push({
      status: isEol ? 'eol' : (cycle.s === 'warn' ? 'warn' : 'active'),
      product: slug, product_url: `https://endoflife.ai/${slug}`, cycle: String(cycle.c),
      eol_date: row.eol_date, eol_date_published: cycle.eol === true ? false : undefined,
      days_until_eol: row.days_until_eol, days_past_eol: row.days_past_eol,
      matched_by: how, purl_matched: purlMatched, purl_type: pt(c.purl), score_url: row.score_url, scored: false,
    });
    const key = slug + ':' + cycle.c;
    if (seen.has(key)) continue;
    seen.add(key);
    results.push(row);
  }
  return { format: parsed.format, components: parsed.components.length, results, unmatched, parsed, annotations, doc };
}

// ── Enriched SBOM output ─────────────────────────────────────────────────────
// Same property schema as POST https://api.endoflife.ai/v1/sbom?enrich=1
// (spec: https://endoflife.ai/sbom-enrichment.json), minus risk scores, which
// the Action does not compute (every matched line carries endoflife:scored=false).
const ENRICH_NS = 'endoflife:';
const ENRICH_ANNOTATOR = 'Tool: endoflife.ai eol-check';
function enrichPairs(a) {
  const pairs = [];
  const put = (k, v) => { if (v !== undefined && v !== null && v !== '') pairs.push([ENRICH_NS + k, String(v)]); };
  put('status', a.status); put('product', a.product); put('product_url', a.product_url); put('cycle', a.cycle);
  put('eol_date', a.eol_date); put('days_until_eol', a.days_until_eol); put('days_past_eol', a.days_past_eol);
  put('matched_by', a.matched_by); put('purl_matched', a.purl_matched); put('purl_type', a.purl_type);
  if (a.eol_date_published === false) put('eol_date_published', 'false');
  put('score_url', a.score_url);
  if (a.reason) put('reason', a.reason);
  if (a.scored === false) put('scored', 'false');
  return pairs;
}
function enrichDoc(doc, r, summary) {
  const now = new Date().toISOString();
  const isOurs = (t) => t && (t.name === 'endoflife.ai eol-check' || t.vendor === 'endoflife.ai');
  const docPairs = [
    ['enriched_at', now], ['components', summary.components], ['matched', summary.matched], ['unique_products', summary.unique_products],
    ['unique_lines', summary.unique_lines], ['past_eol', summary.past_eol], ['not_tracked', summary.not_tracked], ['gate', summary.gate],
    ['gate_policy', summary.gate_policy], ['strict', 'false'], ['purl_map_generated', summary.purl_map_generated],
    ['purl_map', 'https://endoflife.ai/purl-map.json'], ['docs', 'https://endoflife.ai/sbom-enrichment.json'],
  ].filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => [ENRICH_NS + k, String(v)]);
  if (r.parsed.format === 'CycloneDX') {
    r.parsed.components.forEach((c, i) => {
      const node = c.ref, a = r.annotations[i]; if (!node || !a) return;
      const kept = (Array.isArray(node.properties) ? node.properties : []).filter((p) => !(p && typeof p.name === 'string' && p.name.startsWith(ENRICH_NS)));
      node.properties = kept.concat(enrichPairs(a).map(([name, value]) => ({ name, value })));
    });
    doc.metadata = doc.metadata && typeof doc.metadata === 'object' ? doc.metadata : {};
    const md = doc.metadata;
    md.properties = (Array.isArray(md.properties) ? md.properties : []).filter((p) => !(p && typeof p.name === 'string' && p.name.startsWith(ENRICH_NS))).concat(docPairs.map(([name, value]) => ({ name, value })));
    const tool14 = { vendor: 'endoflife.ai', name: 'endoflife.ai eol-check', version: ACTION_VERSION };
    const tool15 = { type: 'application', name: 'endoflife.ai eol-check', version: ACTION_VERSION, supplier: { name: 'endoflife.ai', url: ['https://endoflife.ai'] } };
    if (Array.isArray(md.tools)) md.tools = md.tools.filter((t) => !isOurs(t)).concat([tool14]);
    else if (md.tools && typeof md.tools === 'object') md.tools.components = (Array.isArray(md.tools.components) ? md.tools.components : []).filter((t) => !isOurs(t)).concat([tool15]);
    else md.tools = parseFloat(String(doc.specVersion || '1.5')) >= 1.5 ? { components: [tool15] } : [tool14];
    return doc;
  }
  const notOurs = (x) => !(x && x.annotator === ENRICH_ANNOTATOR);
  r.parsed.components.forEach((c, i) => {
    const node = c.ref, a = r.annotations[i]; if (!node || !a) return;
    node.annotations = (Array.isArray(node.annotations) ? node.annotations : []).filter(notOurs)
      .concat([{ annotationType: 'OTHER', annotator: ENRICH_ANNOTATOR, annotationDate: now, comment: enrichPairs(a).map(([k, v]) => k + '=' + v).join('; ') }]);
  });
  doc.annotations = (Array.isArray(doc.annotations) ? doc.annotations : []).filter(notOurs)
    .concat([{ annotationType: 'OTHER', annotator: ENRICH_ANNOTATOR, annotationDate: now, comment: docPairs.map(([k, v]) => k + '=' + v).join('; ') }]);
  return doc;
}

(async () => {
  const root = process.env.GITHUB_WORKSPACE || process.cwd();
  const failOn = input('fail-on', 'eol').toLowerCase();
  const warnDays = parseInt(input('warn-days', '90'), 10) || 90;
  const sbomInput = input('sbom', '');
  const sbomOutput = input('sbom-output', '');
  const items = [];

  if (input('scan', 'true') !== 'false') items.push(...detect(root));
  for (const p of input('products', '').split(',').map((s) => s.trim()).filter(Boolean)) {
    const [slug, version] = p.split(':').map((s) => s.trim().toLowerCase());
    if (slug && version) items.push({ slug, version, file: null });
  }
  const seen = new Set();
  const unique = items.filter((x) => { const k = x.slug + ':' + x.version; if (seen.has(k)) return false; seen.add(k); return true; });

  const apiKey = input('api-key', '') || process.env.ENDOFLIFE_API_KEY || '';
  if (apiKey) console.log(`::add-mask::${apiKey}`);
  let dbProducts = null; // scanner-db.json, downloaded at most once

  // SBOM files: resolved locally against scanner-db.json (one download).
  const sbomResults = [];
  let sbomComponents = 0, sbomUnmatched = [];
  const sbomFiles = sbomInput.split(',').map((s) => s.trim()).filter(Boolean);
  if (sbomFiles.length) {
    let products;
    try { products = dbProducts = await loadScannerDb(); }
    catch (e) { annotate('error', `eol-check: could not load endoflife.ai/scanner-db.json (${e.message}) — SBOM components not checked.`); process.exitCode = 1; products = null; }
    if (products) {
      const purlLookup = buildPurlLookup(products);
      const nameLookup = buildNameLookup(products);
      for (const f of sbomFiles) {
        let text;
        try { text = fs.readFileSync(path.resolve(root, f), 'utf8'); }
        catch { annotate('error', `eol-check: SBOM file not found: ${f}`, f); process.exitCode = 1; continue; }
        const r = checkSbomFile(f, text, products, purlLookup, nameLookup);
        if (r.error) { annotate('error', `eol-check: ${f} is ${r.error}`, f); process.exitCode = 1; continue; }
        sbomComponents += r.components;
        sbomUnmatched.push(...r.unmatched);
        if (sbomOutput) {
          // One enriched document per input: a directory target gets <name>.enriched.<ext>,
          // a file target is used as-is for a single input (suffixed for several).
          let outPath = path.resolve(root, sbomOutput);
          const isDir = sbomOutput.endsWith('/') || sbomOutput.endsWith('\\') || (fs.existsSync(outPath) && fs.statSync(outPath).isDirectory());
          // sbom.cdx.json -> sbom.enriched.cdx.json (suffix goes before the first extension)
          if (isDir) { const b = path.basename(f); outPath = path.join(outPath, b.includes('.') ? b.replace(/^([^.]+)/, '$1.enriched') : b + '.enriched.json'); }
          else if (sbomFiles.length > 1) { const i = sbomFiles.indexOf(f); if (i > 0) { const b = path.basename(outPath); outPath = path.join(path.dirname(outPath), b.includes('.') ? b.replace(/^([^.]+)/, `$1.${i + 1}`) : `${b}.${i + 1}`); } }
          const uniqProducts = new Set(r.results.map((x) => x.slug));
          const eolLines = r.results.filter((x) => x.is_eol).length;
          const soonest = r.results.filter((x) => !x.is_eol && x.days_until_eol != null).reduce((m, x) => (m == null || x.days_until_eol < m ? x.days_until_eol : m), null);
          const gate = eolLines > 0 ? 'fail' : (soonest != null && soonest <= warnDays ? 'warn' : 'pass');
          // r.doc is the object the annotations' refs point into (a fresh parse would be a different tree)
          const enriched = enrichDoc(r.doc, r, {
            components: r.components, matched: r.results.length, unique_products: uniqProducts.size, unique_lines: r.results.length,
            past_eol: eolLines, not_tracked: r.unmatched.length, gate, gate_policy: `fail_on=${failOn}; warn_days=${warnDays}`,
            purl_map_generated: loadScannerDb.generated,
          });
          try { fs.mkdirSync(path.dirname(outPath), { recursive: true }); fs.writeFileSync(outPath, JSON.stringify(enriched, null, 2) + '\n'); console.log(`eol-check: enriched SBOM written to ${path.relative(root, outPath)} (gate: ${gate})`); }
          catch (e) { annotate('error', `eol-check: could not write ${outPath}: ${e.message}`); process.exitCode = 1; }
        }
        for (const row of r.results) {
          const k = row.slug + ':' + row.version;
          if (seen.has(k)) continue;
          seen.add(k);
          sbomResults.push(row);
        }
        console.log(`eol-check: ${f} (${r.format}) — ${r.components} components, ${r.results.length} tracked, ${r.unmatched.length} not tracked`);
      }
    }
  }

  if (!unique.length && !sbomResults.length) {
    if (sbomComponents) console.log(`eol-check: ${sbomComponents} SBOM components, none tracked by endoflife.ai (nothing to verdict — never a guess).`);
    else console.log('eol-check: nothing detected to check (add the `products` or `sbom` input).');
    return;
  }

  // Repo-scan and `products` items: the live API with a key, else the local database.
  const local = async () => {
    if (!dbProducts) dbProducts = await loadScannerDb();
    return dbProducts;
  };
  let checked = [];
  try {
    if (apiKey) {
      checked = await Promise.all(unique.map((i) => check(i, apiKey)));
      const fb = checked.filter((r) => r.fallback);
      if (fb.length) {
        annotate('notice', `eol-check: api.endoflife.ai answered HTTP ${fb[0].status} for the API key; ${fb.length} check(s) resolved from endoflife.ai/scanner-db.json instead. Check the key at https://endoflife.ai/api.`);
        const db = await local();
        checked = checked.map((r) => (r.fallback ? checkLocal({ slug: r.slug, version: r.version, file: r.file }, db) : r));
      }
    } else if (unique.length) {
      const db = await local();
      checked = unique.map((i) => checkLocal(i, db));
    }
  } catch (e) {
    annotate('error', `eol-check: could not load endoflife.ai/scanner-db.json (${e.message}) — repo checks not run. Add an api-key input to use the API instead.`);
    process.exitCode = 1;
  }
  const results = [...checked, ...sbomResults];
  let eolCount = 0, approaching = 0;
  const rows = [];
  for (const r of results) {
    const label = `${r.slug} ${r.version}`;
    if (r.unknown) { annotate('notice', `eol-check: ${label} is not tracked by endoflife.ai — skipped.`, r.file); rows.push(`| ${label} | — | not tracked | ${r.file || 'input'} |`); continue; }
    if (r.error) { annotate('notice', `eol-check: ${label} lookup failed (${r.error}) — skipped.`, r.file); continue; }
    const where = r.component ? `${r.file} · ${r.component}` : (r.file || 'products input');
    if (r.is_eol) {
      eolCount++;
      const ago = r.days_past_eol != null ? ` (${r.days_past_eol} days ago)` : '';
      const since = r.eol_date ? ` since ${r.eol_date}` : (r.eol_unpublished ? ' (vendor publishes no date)' : '');
      annotate('error', `${label} is END OF LIFE${since}${ago} — no more security fixes. ${r.score_url || ''}`, r.file);
      rows.push(`| ${label} | 🔴 EOL | ${r.eol_date || '—'} | ${where} |`);
    } else if (r.days_until_eol != null && r.days_until_eol <= warnDays) {
      approaching++;
      annotate('warning', `${label} reaches end of life in ${r.days_until_eol} days (${r.eol_date}). Plan the upgrade. ${r.score_url || ''}`, r.file);
      rows.push(`| ${label} | 🟡 EOL in ${r.days_until_eol}d | ${r.eol_date} | ${where} |`);
    } else {
      rows.push(`| ${label} | 🟢 supported | ${r.eol_date || '—'} | ${where} |`);
    }
  }
  if (sbomUnmatched.length) {
    const sample = sbomUnmatched.slice(0, 5).join(', ');
    annotate('notice', `eol-check: ${sbomUnmatched.length} SBOM component${sbomUnmatched.length === 1 ? '' : 's'} not tracked by endoflife.ai — no verdict, never a guess (e.g. ${sample}${sbomUnmatched.length > 5 ? ', …' : ''}).`);
  }

  const report = [
    '### EOL Check',
    '',
    '| Product | Status | EOL date | Found in |',
    '|---|---|---|---|',
    ...rows,
    '',
    `Data: [endoflife.ai](https://endoflife.ai) · ${results.length} checked · ${eolCount} EOL · ${approaching} approaching` +
      (sbomComponents ? ` · SBOM: ${sbomComponents} components, ${sbomResults.length} tracked, ${sbomUnmatched.length} not tracked` : ''),
  ].join('\n');
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, report + '\n');
  if (process.env.GITHUB_OUTPUT) {
    const out = [`eol-count=${eolCount}`, `approaching-count=${approaching}`, `checked-count=${results.length}`,
      `sbom-components=${sbomComponents}`, `unmatched-count=${sbomUnmatched.length}`,
      'report<<EOL_CHECK_EOF', report, 'EOL_CHECK_EOF'].join('\n') + '\n';
    fs.appendFileSync(process.env.GITHUB_OUTPUT, out);
  }
  console.log(report);

  const fail = (failOn === 'eol' && eolCount > 0) || (failOn === 'approaching' && (eolCount > 0 || approaching > 0));
  if (fail) {
    console.log(`::error::eol-check failed: ${eolCount} end-of-life, ${approaching} approaching (fail-on: ${failOn}).`);
    // exitCode (not process.exit) lets pending handles drain — process.exit here
    // trips a libuv assertion on Windows Node with in-flight fetch teardown.
    process.exitCode = 1;
  }
})().catch((e) => { console.log(`::error::eol-check crashed: ${esc(e && e.stack || e)}`); process.exitCode = 1; });
