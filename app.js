// ─── SECURITY CONFIG ────────────────────────────────────────────────────────
// All API calls (Ahrefs + Google Sheets) go through the Cloudflare Worker.
// The worker is intentionally unauthenticated — abuse is mitigated by:
//   1. A hostname allowlist on the Ahrefs `target=` parameter (worker-side).
//   2. Cloudflare dashboard Rate Limiting rules on the worker route.
// Sheet data is non-confidential; sheet IDs live server-side in worker.js.
const WORKER_BASE = 'https://ahrefs-proxy.nicole-lehman.workers.dev';

// SECURITY v3: Validates that a URL uses http/https before inserting into href.
// Prevents javascript: URI XSS from Ahrefs/Muckrack API responses.
function safeHref(url) {
  try {
    const u = new URL(String(url || ''));
    return (u.protocol === 'https:' || u.protocol === 'http:') ? String(url) : '#';
  } catch(e) { return '#'; }
}

// SECURITY v4: Prevents formula injection when pasting into Excel / Google Sheets.
// Prefixes cells that start with =, +, -, @, tab, or newline with a single quote.
function csvSafe(v) {
  const s = String(v || '');
  return /^[=+\-@\t\r\n]/.test(s) ? "'" + s : s;
}
// ─── END SECURITY CONFIG ────────────────────────────────────────────────────

const TODAY = new Date().toISOString().slice(0,10);
const DOMAIN_SITE = {
  'clever':'c','anytime estimate':'a','anytimeestimate':'a',
  'real estate witch':'w','rew':'w','bestinterest':'b',
  'best interest':'b','best interest financial':'b',
  'clever offers':'o','home bay':'h','homebay':'h'
};
const OUTLET_MAP = {
  'finance.yahoo.com':'Yahoo Finance','yahoo.com':'Yahoo','aol.com':'AOL',
  'blackenterprise.com':'Black Enterprise','yourtango.com':'YourTango',
  'chanty.com':'Chanty','grokipedia.com':'Grokipedia',
  'themalaysianreserve.com':'The Malaysian Reserve',
  'blackowned.us.hivebrite.com':'Black Owned','hivebrite.com':'Hivebrite',
  'islands.com':'Islands.com','hn.nuxt.dev':'Hacker News',
  'mecktimes.com':'Meck Times','mykukun.com':'MyKukun',
  'lrgrealty.com':'LRG Realty','karenmercer.myagent.site':'',
  'lisaandrade.myagent.site':'','businessinsider.com':'Business Insider',
  'forbes.com':'Forbes','nytimes.com':'New York Times',
  'washingtonpost.com':'Washington Post','cnbc.com':'CNBC',
  'marketwatch.com':'MarketWatch','reuters.com':'Reuters',
  'axios.com':'Axios','lifehacker.com':'Lifehacker',
  'bankrate.com':'Bankrate','investopedia.com':'Investopedia',
  'realtor.com':'Realtor.com','zillow.com':'Zillow',
  'housingwire.com':'HousingWire','inman.com':'Inman',
  'cnn.com':'CNN','cbsnews.com':'CBS News','nbcnews.com':'NBC News',
  'foxbusiness.com':'Fox Business','wsj.com':'Wall Street Journal',
  'usatoday.com':'USA Today','time.com':'TIME','money.com':'Money',
  'kiplinger.com':'Kiplinger','msn.com':'MSN','reddit.com':'Reddit',
  'medium.com':'Medium','smartasset.com':'SmartAsset',
  'nerdwallet.com':'NerdWallet','lendingtree.com':'LendingTree',
  'apartmenttherapy.com':'Apartment Therapy',
};
const SYNDICATION_DOMAINS = new Set([
  'finance.yahoo.com','yahoo.com','msn.com','aol.com',
  'blackowned.us.hivebrite.com','hivebrite.com','news.google.com'
]);
const SITE_LABELS = {c:'listwithclever',w:'realestatewitch',b:'bestinterest',a:'anytimeestimate',o:'cleveroffers',h:'homebay'};
function getSiteKey(domain) {
  if (!domain) return 'c';
  const d = domain.trim().toLowerCase();
  for (const [k,v] of Object.entries(DOMAIN_SITE)) {
    if (d === k || d.includes(k)) return v;
  }
  return 'c';
}
function getSiteFromUrl(url) {
  if (!url) return '';
  try {
    const h = new URL(url).hostname.replace(/^www\./,'');
    if (h.includes('realestatewitch')) return 'w';
    if (h.includes('bestinterest')) return 'b';
    if (h.includes('anytimeestimate')) return 'a';
    if (h.includes('cleveroffers')) return 'o';
    if (h.includes('homebay')) return 'h';
    if (h.includes('listwithclever')) return 'c';
    return '';
  } catch(e){ return ''; }
}
function getOutlet(url) {
  try {
    const h = new URL(url).hostname.replace(/^www\./,'');
    if (OUTLET_MAP[h] !== undefined) return OUTLET_MAP[h];
    for (const [k,v] of Object.entries(OUTLET_MAP)) {
      if (h === k || h.endsWith('.'+k)) return v;
    }
    const parts = h.split('.');
    if (parts.length >= 2) {
      const n = parts[parts.length-2];
      if (!['co','myagent','hivebrite'].includes(n)) return n.charAt(0).toUpperCase()+n.slice(1);
    }
    return '';
  } catch(e){ return ''; }
}
function getSource(studyName, covUrl) {
  try {
    const p = new URL(covUrl).searchParams;
    if (p.has('utm_source')||p.has('utm_medium')||p.has('utm_campaign')) return 'Press release';
  } catch(e){}
  if (/content/i.test(studyName)) return 'Content';
  try {
    const h = new URL(covUrl).hostname.replace(/^www\./,'');
    if (SYNDICATION_DOMAINS.has(h)) return 'Syndication';
  } catch(e){}
  return '';
}
function isPagination(url) { return /\/page\/\d+/.test(url); }
function isFiltered(url) {
  try {
    const h = new URL(url).hostname.replace(/^www\./,'');
    const BLOCKED = [
      'homezada.com',
      'mykukun.com',
      'hn.nuxt.dev',
    ];
    if (BLOCKED.some(b => h === b || h.endsWith('.'+b))) return true;
    if (h.endsWith('.nuxt.dev')) return true;
    return false;
  } catch(e){ return false; }
}
// Excludes forum/blog coverage: known UGC platforms, forum-ish subdomains,
// and forum URL path markers. Conservative on paths (no bare `/blog/`) to
// avoid dropping legit outlets that host editorial in a `/blog/` subsection.
function isForumOrBlog(url) {
  if (!url) return false;
  try {
    const u = new URL(url);
    const h = u.hostname.replace(/^www\./,'').toLowerCase();
    const path = u.pathname.toLowerCase();
    if (/^(forum|forums|community|discuss|discussion|blog|blogs)\./.test(h)) return true;
    const PLATFORMS = [
      'reddit.com','quora.com','stackoverflow.com','ycombinator.com',
      'blogspot.com','wordpress.com','substack.com','tumblr.com','medium.com',
      'ghost.io','typepad.com','livejournal.com',
    ];
    if (PLATFORMS.some(p => h === p || h.endsWith('.'+p))) return true;
    if (h === 'stackexchange.com' || h.endsWith('.stackexchange.com')) return true;
    if (/\/(forum|forums|community|discussion|viewtopic|showthread)(\/|\.|$)/.test(path)) return true;
    return false;
  } catch(e){ return false; }
}
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function drClass(dr){ return dr>=90?'dr-90':dr>=70?'dr-70':dr>=50?'dr-50':'dr-30'; }
function shortUrl(url){ try{ const u=new URL(url); const p=u.pathname; return u.hostname.replace(/^www\./,'')+(p.length>20?p.slice(0,18)+'…':p); }catch(e){ return String(url).slice(0,32); } }
function getDateFrom(){ return document.getElementById('date-from').value||'2026-04-01'; }
function onDateChange(){ document.getElementById('note').textContent='Date changed — click Start Tracking to re-pull for this range.'; loadMuckrackSheet(); }
function srcBadge(src){
  if (!src) return '<span class="em-dash-sm">—</span>';
  const cls = src==='Press release'?'src-pr':src==='Syndication'?'src-syn':src==='Content'?'src-content':'';
  const lbl = src==='Press release'?'PR':src==='Syndication'?'Syn':src;
  return `<span class="src-badge ${cls}">${lbl}</span>`;
}
function setSheetStatus(state, msg) {
  const el = document.getElementById('sheet-status');
  el.className = 'sheet-status ' + state;
  el.innerHTML = `<span class="dot"></span> ${msg}`;
}
function setProgress(pct, msg) {
  document.getElementById('prog').style.width = pct + '%';
  if (msg) document.getElementById('note').textContent = msg;
}
let studies = [];
let ahrefsRows = [];
let muckrackWithLink = [];
let muckrackNoLink = [];
let drFilter = 30;
let trackingStarted = false;
let isLoading = false;
let ahrefsError = '';
function showApiError(msg) {
  const el = document.getElementById('api-error');
  if (!el) return;
  if (msg) {
    const isQuota = /api units?.*(limit|left)|rate limit/i.test(msg);
    el.textContent = isQuota
      ? 'Ahrefs API monthly usage limit reached — Ahrefs is blocking new requests until your billing cycle resets. Coverage data cannot be pulled until then.'
      : 'Ahrefs API error: ' + msg;
    el.classList.add('visible');
  } else {
    el.classList.remove('visible');
    el.textContent = '';
  }
}

// Per-table sort state. Default: newest first by date.
const sortState = {
  'tracked':         { key: 'dateFound', dir: 'desc' },
  'low':             { key: 'dateFound', dir: 'desc' },
  'muckrack-nolink': { key: 'date',      dir: 'desc' },
};
const NUMERIC_KEYS = new Set(['dr','da']);
const DATE_KEYS    = new Set(['dateFound','date']);
function toSortTime(s) {
  if (!s) return 0;
  const t = Date.parse(s);
  return isNaN(t) ? 0 : t;
}
// Normalizes dates for display. ISO dates ("2026-04-11") are parsed as local
// to avoid UTC→local rollback. Already-formatted dates round-trip cleanly.
function formatDate(s) {
  if (!s) return '';
  const iso = String(s).match(/^(\d{4})-(\d{2})-(\d{2})/);
  const d = iso ? new Date(+iso[1], +iso[2]-1, +iso[3]) : new Date(s);
  if (isNaN(d)) return String(s);
  return d.toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' });
}
function sortData(data, key, dir) {
  const mult = dir === 'asc' ? 1 : -1;
  const numeric = NUMERIC_KEYS.has(key);
  const isDate  = DATE_KEYS.has(key);
  return data.slice().sort((a, b) => {
    const av = a[key], bv = b[key];
    if (numeric) return (((+av)||0) - ((+bv)||0)) * mult;
    if (isDate)  return (toSortTime(av) - toSortTime(bv)) * mult;
    const as = String(av == null ? '' : av).toLowerCase();
    const bs = String(bv == null ? '' : bv).toLowerCase();
    if (as === bs) return 0;
    return (as < bs ? -1 : 1) * mult;
  });
}
function updateSortIndicators(tableKey) {
  const panel = document.getElementById('panel-' + tableKey);
  if (!panel) return;
  const st = sortState[tableKey];
  panel.querySelectorAll('th[data-sort]').forEach(th => {
    th.classList.remove('sort-asc','sort-desc');
    if (th.dataset.sort === st.key) th.classList.add(st.dir === 'asc' ? 'sort-asc' : 'sort-desc');
  });
}
// Proper CSV tokenizer — state machine that handles quoted fields with
// embedded commas, doubled-quote escapes (""), and newlines inside quotes.
// Returns an array of rows, each row an array of field strings.
function parseCSVRows(text) {
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  const len = text.length;
  for (let i = 0; i < len; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i+1] === '"') { field += '"'; i++; continue; }
        inQuotes = false;
        continue;
      }
      field += c;
      continue;
    }
    if (c === '"') { inQuotes = true; continue; }
    if (c === ',') { row.push(field); field = ''; continue; }
    if (c === '\r') continue;
    if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; continue; }
    field += c;
  }
  if (field !== '' || row.length > 0) { row.push(field); rows.push(row); }
  return rows;
}
async function parseCSV(text) {
  const rows = parseCSVRows(text);
  const result = [];
  for (let i = 1; i < rows.length; i++) {
    const clean = rows[i].map(c => c.trim());
    const name = clean[0];
    const domain = clean[2];
    const url = clean[5];
    if (name && url && url.startsWith('http')) {
      result.push({ name, url, site: getSiteKey(domain) });
    }
  }
  const seenPaths = new Map();
  const seenHomepages = new Map();
  for (const s of result) {
    try {
      const u = new URL(s.url);
      const domain = u.hostname.replace(/^www\./, '');
      const path = u.pathname.replace(/\/$/, '').replace(/#.*$/, '');
      if (path === '' || path === '/') {
        seenHomepages.set(domain, s);
      } else {
        seenPaths.set(domain + path, s);
      }
    } catch(e) { seenPaths.set(s.url, s); }
  }
  // Specific studies first so their results win deduplication over homepage catch-alls
  return Array.from(seenPaths.values()).concat(Array.from(seenHomepages.values()));
}

// SECURITY: Sheet CSV is now fetched via the authenticated Cloudflare Worker.
// The Google Sheet IDs no longer appear in this file.
async function loadStudies() {
  setSheetStatus('loading', 'Loading studies from Google Sheet…');
  try {
    const res = await fetch(`${WORKER_BASE}/sheets/studies`);
    if (!res.ok) throw new Error('fetch failed');
    const text = await res.text();
    studies = await parseCSV(text);
    const _todayFmt = new Date().toLocaleDateString('en-US', {month:'short', day:'numeric', year:'numeric'});
    setSheetStatus('ok', `${studies.length} studies loaded from Google Sheet — auto-updated ${_todayFmt}`);
    return true;
  } catch(e) {
    setSheetStatus('err', `Could not load studies: ${e.message}`);
    return false;
  }
}

// Domain-level fetch: one Ahrefs call per domain. Studies are matched to
// backlinks client-side from the Google Sheet. Cuts API usage ~10x vs the
// old per-study approach (6 calls instead of 234).
const SITE_DOMAINS = [
  { site: 'c', url: 'https://listwithclever.com/',  label: 'listwithclever'  },
  { site: 'w', url: 'https://realestatewitch.com/', label: 'realestatewitch' },
  { site: 'b', url: 'https://bestinterest.com/',    label: 'bestinterest'    },
  { site: 'a', url: 'https://anytimeestimate.com/', label: 'anytimeestimate' },
  { site: 'o', url: 'https://cleveroffers.com/',    label: 'cleveroffers'    },
  { site: 'h', url: 'https://homebay.com/',         label: 'homebay'         },
];
const OWN_HOSTS = SITE_DOMAINS.map(d => {
  try { return new URL(d.url).hostname.replace(/^www\./,'').toLowerCase(); } catch(e) { return ''; }
}).filter(Boolean);
// Excludes internal links (one of our own pages linking to another of our pages).
function isOwnSite(url) {
  if (!url) return false;
  try {
    const h = new URL(url).hostname.replace(/^www\./,'').toLowerCase();
    return OWN_HOSTS.some(dh => h === dh || h.endsWith('.' + dh));
  } catch(e) { return false; }
}

async function fetchDomainBacklinks(domainInfo, cutoff) {
  const where = JSON.stringify({"and":[
    {"field":"domain_rating_source","is":["gte",1]},
    {"field":"first_seen","is":["gte", cutoff]}
  ]});
  const workerUrl = `${WORKER_BASE}?target=` + encodeURIComponent(domainInfo.url) + '&where=' + encodeURIComponent(where) + '&mode=prefix';
  try {
    const res = await fetch(workerUrl);
    const data = await res.json();
    if (data.error) {
      ahrefsError = data.error;
      showApiError(data.error);
      return [];
    }
    return Array.isArray(data.backlinks) ? data.backlinks : [];
  } catch(e) {
    return [];
  }
}

// Per-site index of studies sorted by path length desc. Longest-path match
// wins when multiple studies share a path prefix (prevents a shorter parent
// study from grabbing hits that belong to a more specific child).
function buildStudyIndex() {
  const idx = {};
  for (const s of studies) {
    try {
      const sPath = new URL(s.url).pathname.replace(/\/$/, '').replace(/#.*$/, '');
      if (sPath.length <= 1) continue;
      (idx[s.site] = idx[s.site] || []).push(Object.assign({}, s, { path: sPath }));
    } catch(e) {}
  }
  for (const k in idx) idx[k].sort((a,b) => b.path.length - a.path.length);
  return idx;
}
function findStudyForPath(ourPath, site, studyIndex) {
  const list = studyIndex[site] || [];
  for (const c of list) {
    if (ourPath === c.path || ourPath.startsWith(c.path + '/')) return c;
  }
  return null;
}

function processBacklink(b, domainInfo, studyIndex) {
  const covUrl = b.url_from || '';
  const ourUrl = b.url_to   || '';
  if (!covUrl || !ourUrl) return null;
  if (isOwnSite(covUrl)) return null;
  if (covUrl.includes('homezada.com') || covUrl.includes('mykukun.com') || covUrl.includes('nuxt.dev')) return null;
  const ourPath = ourUrl.replace(/^https?:\/\/[^\/]+/, '') || '/';
  const site    = domainInfo.site;
  const matched = findStudyForPath(ourPath, site, studyIndex);
  const studyName = matched ? matched.name : ('General — ' + (SITE_LABELS[site] || site));
  return {
    study: studyName,
    outlet: getOutlet(covUrl),
    dr: Math.round(b.domain_rating_source || 0),
    covUrl,
    ourUrl,
    ourPath,
    site,
    firstSeen: b.first_seen ? b.first_seen.slice(0,10) : '',
    dateFound: b.first_seen ? b.first_seen.slice(0,10) : '',
    source: getSource(studyName, covUrl),
    isGeneral: !matched,
  };
}

async function fullRefresh() {
  if (isLoading) return;
  isLoading = true;
  const btn = document.getElementById('refresh-btn');
  btn.disabled = true;
  ahrefsRows = [];
  ahrefsError = '';
  showApiError('');
  trackingStarted = true;
  await loadStudies();
  loadMuckrackSheet();
  if (!studies.length) {
    isLoading = false;
    btn.disabled = false;
    return;
  }
  const cutoff = getDateFrom();
  const studyIndex = buildStudyIndex();
  setProgress(0, `Fetching Ahrefs backlinks for ${SITE_DOMAINS.length} domains…`);
  document.getElementById('tbody-tracked').innerHTML = `<tr><td colspan="9" class="loading-cell">Fetching coverage data…</td></tr>`;
  document.getElementById('tbody-low').innerHTML     = `<tr><td colspan="9" class="loading-cell">Fetching coverage data…</td></tr>`;

  let completed = 0;
  const domainResults = await Promise.all(SITE_DOMAINS.map(async d => {
    const backlinks = await fetchDomainBacklinks(d, cutoff);
    completed++;
    setProgress(Math.round((completed / SITE_DOMAINS.length) * 100),
      `Fetched ${completed}/${SITE_DOMAINS.length} domains — ${d.label} returned ${backlinks.length} backlinks`);
    return { d, backlinks };
  }));

  const rows = [];
  for (const { d, backlinks } of domainResults) {
    for (const b of backlinks) {
      const r = processBacklink(b, d, studyIndex);
      if (r) rows.push(r);
    }
  }
  const seen = new Set();
  ahrefsRows = rows.filter(r => {
    const k = r.covUrl + '|' + r.ourUrl;
    if (seen.has(k)) return false;
    seen.add(k); return true;
  });

  const dr30 = ahrefsRows.filter(r => r.dr >= 30).length;
  setProgress(100, `${dr30} DR 30+ hits found — last pulled ${TODAY}`);
  isLoading = false;
  btn.disabled = false;
  render();
}
function filteredRows() {
  const from = getDateFrom();
  const q = document.getElementById('search') ? document.getElementById('search').value.toLowerCase() : '';
  const sf = document.getElementById('site-filter').value;
  const includeGeneral = document.getElementById('include-general') && document.getElementById('include-general').checked;
  const ignoreBlankStudy = document.getElementById('ignore-blank-study') && document.getElementById('ignore-blank-study').checked;
  return ahrefsRows.filter(r => {
    if (r.firstSeen && r.firstSeen < from) return false;
    if (sf && r.site !== sf) return false;
    if (!includeGeneral && r.isGeneral) return false;
    if (ignoreBlankStudy && (!r.study || r.study.trim() === '')) return false;
    if (r.covUrl && (r.covUrl.includes('prnewswire.com') || r.covUrl.includes('newswire.com'))) return false;
    if (r.outlet && r.outlet.toLowerCase().includes('pr newswire')) return false;
    if (isForumOrBlog(r.covUrl)) return false;
    if (q && !r.study.toLowerCase().includes(q) && !r.outlet.toLowerCase().includes(q) && !r.covUrl.toLowerCase().includes(q)) return false;
    return true;
  });
}
function render() {
  const all = filteredRows();
  const ahrefsTracked = all.filter(r=>r.dr>=30);
  const low = all.filter(r=>r.dr<30);
  const showAhrefs = document.getElementById('show-ahrefs') ? document.getElementById('show-ahrefs').checked : true;
  const showMuckrack = document.getElementById('show-muckrack') ? document.getElementById('show-muckrack').checked : true;
  const ahrefsRows30 = showAhrefs ? ahrefsTracked : [];
  const ignoreBlankStudy2 = document.getElementById('ignore-blank-study') && document.getElementById('ignore-blank-study').checked;
  const muckrackRows30 = (showMuckrack && trackingStarted) ? muckrackWithLink.filter(r => !ignoreBlankStudy2 || (r.study && r.study.trim() !== '')) : [];
  const muckNorm = muckrackRows30.map(r => ({
    study: r.study || '', outlet: r.outlet, dr: r.da, covUrl: r.url,
    ourUrl: r.studyUrl || '', ourPath: (r.studyUrl && r.studyUrl.startsWith('http')) ? (() => { try { return new URL(r.studyUrl).pathname; } catch(e) { return ''; } })() : '',
    site: getSiteFromUrl(r.studyUrl || ''), dateFound: r.date, source: getSource(r.study || '', r.url || ''), isMuckrack: true
  }));
  const drThreshold = typeof drFilter === 'number' ? drFilter : 30;
  const combined = ahrefsRows30.concat(muckNorm).filter(r => r.dr >= drThreshold);
  document.getElementById('count-tracked').textContent = combined.length;
  document.getElementById('count-low').textContent = low.length;
  document.getElementById('count-muckrack-nolink').textContent = muckrackNoLink.length;
  const totalDr30 = combined.length;
  const dr90 = combined.filter(r=>r.dr>=90).length;
  const dr70 = combined.filter(r=>r.dr>=70).length;
  const avg = combined.length ? Math.round(combined.reduce((s,r)=>s+r.dr,0)/combined.length) : 0;
  document.getElementById('stats').innerHTML=`
    <div class="stat"><div class="label">DR 30+ hits</div><div class="value">${totalDr30||'—'}</div></div>
    <div class="stat"><div class="label">DR 90+</div><div class="value">${dr90||'—'}</div></div>
    <div class="stat"><div class="label">DR 70+</div><div class="value">${dr70||'—'}</div></div>
    <div class="stat"><div class="label">Avg DR</div><div class="value">${avg||'—'}</div></div>`;
  renderCombined('tbody-tracked', combined);
  renderTable('tbody-low', low, false);
  renderMuckrack();
}
function renderCombined(id, data) {
  const tbody = document.getElementById(id);
  const tableKey = id.replace(/^tbody-/,'');
  updateSortIndicators(tableKey);
  if (!data.length) {
    tbody.innerHTML=`<tr><td colspan="9" class="empty">${trackingStarted ? 'No results match filters' : 'Click \'Start Tracking\' to view results'}</td></tr>`;
    return;
  }
  const st = sortState[tableKey];
  // SECURITY v3: safeHref() used on all URL fields to block javascript: URIs
  tbody.innerHTML = sortData(data, st.key, st.dir).map(r=>`
    <tr>
      <td title="${esc(r.study)}">${esc(r.study)}</td>
      <td title="${esc(r.outlet)}">${r.outlet?esc(r.outlet):'<span class="em-dash">—</span>'}</td>
      <td><span class="dr-badge ${drClass(r.dr)}">${r.dr}</span></td>
      <td title="${esc(r.covUrl)}"><a class="link" href="${safeHref(r.covUrl)}" target="_blank" rel="noopener noreferrer">${esc(shortUrl(r.covUrl))}</a></td>
      <td title="${esc(r.ourUrl||'')}"><a class="link" href="${safeHref(r.ourUrl||'')}" target="_blank" rel="noopener noreferrer">${esc(r.ourUrl ? (r.isMuckrack ? shortUrl(r.ourUrl) : r.ourPath) : '—')}</a></td>
      <td class="td-muted">${esc(formatDate(r.dateFound))}</td>
      <td>${r.site ? '<span class="site-badge s-'+r.site+'">'+(SITE_LABELS[r.site]||r.site)+'</span>' : '<span class="em-dash-sm">—</span>'}</td>
      <td>${srcBadge(r.source)}</td>
      <td><span class="src-badge ${r.isMuckrack ? 'src-muckrack' : 'src-ahrefs'}">${r.isMuckrack ? 'Muckrack' : 'Ahrefs'}</span></td>
    </tr>`).join('');
}
function renderTable(id, data, highDR) {
  const tbody = document.getElementById(id);
  const tableKey = id.replace(/^tbody-/,'');
  updateSortIndicators(tableKey);
  if (!data.length) {
    tbody.innerHTML=`<tr><td colspan="9" class="empty">${trackingStarted ? 'No results match filters' : 'Click \'Start Tracking\' to view results'}</td></tr>`;
    return;
  }
  const st = sortState[tableKey];
  // SECURITY v3: safeHref() used on all URL fields to block javascript: URIs
  tbody.innerHTML = sortData(data, st.key, st.dir).map(r=>`
    <tr>
      <td title="${esc(r.study)}">${esc(r.study)}</td>
      <td title="${esc(r.outlet)}">${r.outlet?esc(r.outlet):'<span class="em-dash">—</span>'}</td>
      <td><span class="dr-badge ${highDR?drClass(r.dr):'dr-low'}">${r.dr}</span></td>
      <td title="${esc(r.covUrl)}"><a class="link" href="${safeHref(r.covUrl)}" target="_blank" rel="noopener noreferrer">${esc(shortUrl(r.covUrl))}</a></td>
      <td title="${esc(r.ourUrl)}"><a class="link" href="${safeHref(r.ourUrl)}" target="_blank" rel="noopener noreferrer">${esc(r.ourPath)}</a></td>
      <td class="td-muted">${esc(formatDate(r.dateFound))}</td>
      <td><span class="site-badge s-${r.site}">${esc(SITE_LABELS[r.site]||r.site)}</span></td>
      <td>${srcBadge(r.source)}</td>
    </tr>`).join('');
}
function renderMuckrack() {
  const tbody2 = document.getElementById('tbody-muckrack-nolink');
  updateSortIndicators('muckrack-nolink');
  if (!trackingStarted) {
    tbody2.innerHTML='<tr><td colspan="5" class="empty">Click \'Start Tracking\' to view results</td></tr>';
  } else if (!muckrackNoLink.length) {
    tbody2.innerHTML='<tr><td colspan="5" class="empty">No unlinked mentions found for this date range — updates hourly</td></tr>';
  } else {
    const st = sortState['muckrack-nolink'];
    tbody2.innerHTML = sortData(muckrackNoLink, st.key, st.dir).map(r=>`
      <tr>
        <td title="${esc(r.headline)}">${esc(r.headline)}</td>
        <td title="${esc(r.outlet)}">${esc(r.outlet)}</td>
        <td><span class="dr-badge ${drClass(r.da)}">${r.da}</span></td>
        <td class="td-muted">${esc(formatDate(r.date))}</td>
        <td title="${esc(r.snippet||'')}" class="td-muted">${esc((r.snippet||'').slice(0,80))}</td>
      </tr>`).join('');
  }
}
function setTab(tab, btn) {
  document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  ['tracked','low','muckrack-nolink'].forEach(t=>{
    document.getElementById('panel-'+t).classList.toggle('panel-hidden', t !== tab);
  });
}
function setDR(val, btn) {
  drFilter=val==='all'?'all':parseInt(val);
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  render();
}
function copyAll(tab) {
  let text = '';
  if (tab==='tracked') {
    const showAhrefs = document.getElementById('show-ahrefs') ? document.getElementById('show-ahrefs').checked : true;
    const showMuckrack = document.getElementById('show-muckrack') ? document.getElementById('show-muckrack').checked : true;
    const ahrefsData = showAhrefs ? filteredRows().filter(r=>r.dr>=30) : [];
    const muckData = showMuckrack ? muckrackWithLink : [];
    const drThreshold = typeof drFilter === 'number' ? drFilter : 30;
    const combined = ahrefsData.concat(muckData.map(r=>({
      study: r.study || '', outlet: r.outlet, covUrl: r.url, ourUrl: r.studyUrl || '', dateFound: r.date, source: 'Muckrack', dr: r.da
    }))).filter(r=>r.dr>=drThreshold);
    const stT = sortState['tracked'];
    // SECURITY v4: csvSafe() prevents formula injection when pasting into Excel / Sheets
    text = sortData(combined, stT.key, stT.dir).map(r=>[r.study, r.outlet, r.covUrl, r.ourUrl, formatDate(r.dateFound), r.source].map(csvSafe).join('\t')).join('\n');
  } else if (tab==='low') {
    const all = filteredRows();
    const data = all.filter(r=>r.dr<30);
    const stL = sortState['low'];
    text = sortData(data, stL.key, stL.dir)
      .map(r=>[r.study, r.outlet, r.covUrl, r.ourUrl, formatDate(r.dateFound), r.source].map(csvSafe).join('\t'))
      .join('\n');
  } else if (tab==='muckrack-nolink') {
    const stM = sortState['muckrack-nolink'];
    text = sortData(muckrackNoLink, stM.key, stM.dir).map(r=>[r.headline, r.outlet, '', '', formatDate(r.date), ''].map(csvSafe).join('\t')).join('\n');
  }
  navigator.clipboard.writeText(text).then(()=>{
    const el = document.getElementById('copy-ok-'+tab);
    el.style.display='inline';
    setTimeout(()=>el.style.display='none', 2000);
  });
}
function parseMuckrackText(text) {
  const withLink = [];
  const noLink = [];
  if (!text || !text.trim()) return { withLink, noLink };
  const chunks = text.split('Add to Coverage Report');
  const dateStr = getDateFrom();
  for (const chunk of chunks) {
    if (!chunk.trim()) continue;
    const daMatch = chunk.match(/Domain Authority:\s*(\d+)/);
    if (!daMatch) continue;
    const da = parseInt(daMatch[1]);
    if (da < 30) continue;
    const urlMatch = chunk.match(/https?:\/\/[^\s"<>]+/);
    const url = urlMatch ? urlMatch[0].replace(/[.,;]+$/, '') : null;
    const lines = chunk.split('\n').map(l=>l.trim()).filter(l=>l.length>10);
    const headline = lines[0] ? lines[0].slice(0,120) : '';
    const outletMatch = chunk.match(/([A-Z][\w\s\-\.]+?)\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+,\s*\d{4}/);
    const outlet = outletMatch ? outletMatch[1].trim().slice(0,60) : '';
    const dateMatch = chunk.match(/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+,\s*\d{4}/);
    const date = dateMatch ? dateMatch[0] : dateStr;
    const snippetMatch = chunk.match(/\d{4}\s+(.+?)(?:Mortgage|Real estate|Domain|UVM)/s);
    const snippet = snippetMatch ? snippetMatch[1].trim().slice(0,120) : '';
    const row = { headline, outlet, da, date, snippet, url };
    if (url) withLink.push(row);
    else noLink.push(row);
  }
  return { withLink, noLink };
}
function parseSheetCSV(text, cutoff, hasUrl) {
  const results = [];
  const rows = parseCSVRows(text).slice(1);
  const year = new Date().getFullYear();
  const newFormat = (rows[0] || []).length >= 7;
  for (const row of rows) {
    const clean = row.map(c => c.trim());
    let study, headline, outlet, da, url, studyUrl, date, snippet;
    if (newFormat && hasUrl) {
      study = clean[0]; headline = clean[1]; outlet = clean[2];
      da = parseInt(clean[3])||0; url = clean[4]; studyUrl = clean[5]; date = clean[6]; snippet = '';
    } else if (newFormat && !hasUrl) {
      study = clean[0]; headline = clean[1]; outlet = clean[2];
      da = parseInt(clean[3])||0; url = null; studyUrl = ''; date = clean[4]; snippet = clean[5]||'';
    } else if (hasUrl) {
      study = ''; headline = clean[0]; outlet = clean[1];
      da = parseInt(clean[2])||0; url = clean[3]; studyUrl = ''; date = clean[4]; snippet = '';
    } else {
      study = ''; headline = clean[0]; outlet = clean[1];
      da = parseInt(clean[2])||0; url = null; studyUrl = ''; date = clean[3]; snippet = clean[4]||'';
    }
    if (!headline) continue;
    if (date) {
      const dateStr = date.includes(',') ? date : date + ', ' + year;
      const rowDate = new Date(dateStr);
      const cutoffDate = new Date(cutoff);
      if (!isNaN(rowDate) && rowDate < cutoffDate) continue;
    }
    results.push({ study, headline, outlet, da, url, studyUrl, date, snippet });
  }
  return results;
}

// SECURITY: Muckrack sheets now fetched via authenticated Cloudflare Worker.
// Google Sheet IDs no longer appear in this file.
async function loadMuckrackSheet() {
  const status = document.getElementById('gmail-status');
  try {
    const cutoff = getDateFrom();
    const [res1, res2] = await Promise.all([
      fetch(`${WORKER_BASE}/sheets/muckrack-link`),
      fetch(`${WORKER_BASE}/sheets/muckrack-nolink`)
    ]);
    const [text1, text2] = await Promise.all([res1.text(), res2.text()]);
    muckrackWithLink = parseSheetCSV(text1, cutoff, true);
    muckrackNoLink = parseSheetCSV(text2, cutoff, false);
    const seenLink = new Set();
    muckrackWithLink = muckrackWithLink.filter(r => {
      const k = r.url + r.headline;
      if (seenLink.has(k)) return false;
      seenLink.add(k); return true;
    });
    muckrackWithLink = muckrackWithLink.filter(r =>
      !r.url || (!r.url.includes('prnewswire.com') && !r.url.includes('newswire.com'))
    );
    muckrackWithLink = muckrackWithLink.filter(r => !isForumOrBlog(r.url));
    muckrackWithLink = muckrackWithLink.filter(r => !r.url || !isOwnSite(r.url));
    const todayFmt = new Date().toLocaleDateString('en-US', {month:'short', day:'numeric', year:'numeric'});
    if (status) status.textContent = trackingStarted ? muckrackWithLink.length + ' Muckrack results — updates hourly' : 'Click Start Tracking to load';
    render();
  } catch(e) {
    if (status) status.textContent = 'Could not load Muckrack sheet';
  }
}
function onDateChange(){
  document.getElementById('note').textContent='Date changed — click Start Tracking to re-pull for this range.';
  loadMuckrackSheet();
}
// ── Event listeners (replaces inline onclick/onchange/oninput attrs) ──────────
document.getElementById('date-from').addEventListener('change', onDateChange);
document.getElementById('site-filter').addEventListener('change', render);
document.getElementById('refresh-btn').addEventListener('click', fullRefresh);
document.getElementById('search').addEventListener('input', render);
document.getElementById('show-ahrefs').addEventListener('change', render);
document.getElementById('show-muckrack').addEventListener('change', render);
document.getElementById('include-general').addEventListener('change', render);
document.getElementById('ignore-blank-study').addEventListener('change', render);

// Tab buttons (identified by data-tab attribute)
document.querySelectorAll('[data-tab]').forEach(btn => {
  btn.addEventListener('click', function() { setTab(this.dataset.tab, this); });
});

// Copy buttons (identified by data-copy attribute)
document.querySelectorAll('[data-copy]').forEach(btn => {
  btn.addEventListener('click', function() { copyAll(this.dataset.copy); });
});

// DR filter buttons (identified by data-dr attribute)
document.querySelectorAll('[data-dr]').forEach(btn => {
  btn.addEventListener('click', function() { setDR(this.dataset.dr, this); });
});

// Column header sort. Click toggles direction on the same column,
// or switches to a new column (default desc).
document.querySelectorAll('th[data-sort]').forEach(th => {
  th.addEventListener('click', function() {
    const panel = this.closest('[id^="panel-"]');
    if (!panel) return;
    const tableKey = panel.id.replace(/^panel-/,'');
    const st = sortState[tableKey];
    if (!st) return;
    if (st.key === this.dataset.sort) {
      st.dir = st.dir === 'asc' ? 'desc' : 'asc';
    } else {
      st.key = this.dataset.sort;
      st.dir = 'desc';
    }
    render();
  });
});

// On load
const todayStr = new Date().toISOString().slice(0, 10);
document.getElementById('date-from').value = todayStr;
loadStudies().then(() => {
  document.getElementById('note').textContent = studies.length
    ? `${studies.length} studies ready — click "Start Tracking" to pull coverage data.`
    : 'Could not load studies — check your Google Sheet is published as CSV.';
  render();
});
loadMuckrackSheet();
