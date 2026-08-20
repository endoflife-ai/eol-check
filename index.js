// eol-check — fail CI when the stack runs end-of-life software.
// Zero dependencies; Node 20+. Data: https://api.endoflife.ai (free, no key).
'use strict';
const fs = require('fs');
const path = require('path');

const API = 'https://api.endoflife.ai/v1/status';
const UA = 'eol-check-action/1.0 (+https://github.com/endoflife-ai/eol-check)';

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

async function check(item) {
  const url = `${API}/${encodeURIComponent(item.slug)}/${encodeURIComponent(item.version)}`;
  try {
    const res = await fetch(url, { headers: { 'User-Agent': UA } });
    if (res.status === 404) return { ...item, unknown: true };
    if (!res.ok) return { ...item, error: `HTTP ${res.status}` };
    return { ...item, ...(await res.json()) };
  } catch (e) {
    return { ...item, error: String(e && e.message || e) };
  }
}

(async () => {
  const root = process.env.GITHUB_WORKSPACE || process.cwd();
  const failOn = input('fail-on', 'eol').toLowerCase();
  const warnDays = parseInt(input('warn-days', '90'), 10) || 90;
  const items = [];

  if (input('scan', 'true') !== 'false') items.push(...detect(root));
  for (const p of input('products', '').split(',').map((s) => s.trim()).filter(Boolean)) {
    const [slug, version] = p.split(':').map((s) => s.trim().toLowerCase());
    if (slug && version) items.push({ slug, version, file: null });
  }
  const seen = new Set();
  const unique = items.filter((x) => { const k = x.slug + ':' + x.version; if (seen.has(k)) return false; seen.add(k); return true; });

  if (!unique.length) {
    console.log('eol-check: nothing detected to check (add the `products` input for manual pairs).');
    return;
  }

  const results = await Promise.all(unique.map(check));
  let eolCount = 0, approaching = 0;
  const rows = [];
  for (const r of results) {
    const label = `${r.slug} ${r.version}`;
    if (r.unknown) { annotate('notice', `eol-check: ${label} is not tracked by endoflife.ai — skipped.`, r.file); rows.push(`| ${label} | — | not tracked | ${r.file || 'input'} |`); continue; }
    if (r.error) { annotate('notice', `eol-check: ${label} lookup failed (${r.error}) — skipped.`, r.file); continue; }
    const where = r.file || 'products input';
    if (r.is_eol) {
      eolCount++;
      const ago = r.days_past_eol != null ? ` (${r.days_past_eol} days ago)` : '';
      annotate('error', `${label} is END OF LIFE${r.eol_date ? ` since ${r.eol_date}` : ''}${ago} — no more security fixes. ${r.score_url || ''}`, r.file);
      rows.push(`| ${label} | 🔴 EOL | ${r.eol_date || '—'} | ${where} |`);
    } else if (r.days_until_eol != null && r.days_until_eol <= warnDays) {
      approaching++;
      annotate('warning', `${label} reaches end of life in ${r.days_until_eol} days (${r.eol_date}). Plan the upgrade. ${r.score_url || ''}`, r.file);
      rows.push(`| ${label} | 🟡 EOL in ${r.days_until_eol}d | ${r.eol_date} | ${where} |`);
    } else {
      rows.push(`| ${label} | 🟢 supported | ${r.eol_date || '—'} | ${where} |`);
    }
  }

  const report = [
    '### EOL Check',
    '',
    '| Product | Status | EOL date | Found in |',
    '|---|---|---|---|',
    ...rows,
    '',
    `Data: [endoflife.ai](https://endoflife.ai) · ${results.length} checked · ${eolCount} EOL · ${approaching} approaching`,
  ].join('\n');
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, report + '\n');
  if (process.env.GITHUB_OUTPUT) {
    const out = [`eol-count=${eolCount}`, `approaching-count=${approaching}`, `checked-count=${results.length}`,
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
