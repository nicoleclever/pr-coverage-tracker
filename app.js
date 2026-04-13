// ─── SECURITY CONFIG ────────────────────────────────────────────────────────
// All API calls (Ahrefs + Google Sheets) now go through the Cloudflare Worker.
// Sheet IDs are no longer exposed in this file — they live in worker.js only.
// Generate a secret at https://generate-secret.vercel.app/32 and set the same
// value as SECRET in worker.js.
const WORKER_BASE   = 'https://ahrefs-proxy.nicole-lehman.workers.dev';
const WORKER_SECRET = 'e853e9732139794d22843e46fb987a2b650b20f030e5a8d3398ca2ebe4fcfc48';

// SECURITY v2: Attach Bearer token to every worker request
function authHeaders() {
  return { 'Authorization': `Bearer ${WORKER_SECRET}` };
}

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
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function drClass(dr){ return dr>=90?'dr-90':dr>=70?'dr-70':dr>=50?'dr-50':'dr-30'; }
function shortUrl(url){ try{ const u=new URL(url); const p=u.pathname; return u.hostname.replace(/^www\./,'')+(p.length>20?p.slice(0,18)+'…':p); }catch(e){ return String(url).slice(0,32); } }
function getDateFrom(){ return document.getElementById('date-from').value||'2026-04-01'; }
function onDateChange(){ document.getElementById('note').textContent='Date changed — click Start Tracking to re-pull for this range.'; loadMuckrackSheet(); }
function srcBadge(src){
  if (!src) return '<span style="color:#bbb;font-size:12px;">—</span>';
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
async function parseCSV(text) {
  const lines = text.trim().split(/\r?\n/);
  const result = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].match(/(".*?"|[^,]+|(?<=,)(?=,)|^(?=,)|(?<=,)$)/g) || lines[i].split(',');
    const clean = cols.map(c => c.replace(/^"|"$/g,'').trim());
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
      const path = u.pathname.replace(/\/$/, '').replace(/#.*$/, '');
      if (path === '' || path === '/') {
        const domain = u.hostname.replace(/^www\./, '');
        seenHomepages.set(domain, s);
      } else {
        seenPaths.set(path, s);
      }
    } catch(e) { seenPaths.set(s.url, s); }
  }
  return Array.from(seenHomepages.values()).concat(Array.from(seenPaths.values()));
}

// SECURITY: Sheet CSV is now fetched via the authenticated Cloudflare Worker.
// The Google Sheet IDs no longer appear in this file.
async function loadStudies() {
  setSheetStatus('loading', 'Loading studies from Google Sheet…');
  try {
    const res = await fetch(`${WORKER_BASE}/sheets/studies`, { headers: authHeaders() });
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

async function fetchAhrefs(name, url, cutoff) {
  const where = JSON.stringify({"and":[
    {"field":"domain_rating_source","is":["gte",1]},
    {"field":"first_seen","is":["gte", cutoff]}
  ]});
  let studyPath = '/';
  let targetUrl = url;
  try {
    const u = new URL(url);
    studyPath = u.pathname.replace(/\/$/, '') || '/';
    if (studyPath !== '/' && studyPath !== '') {
      targetUrl = u.origin + studyPath;
    }
  } catch(e) {}
  const workerUrl = `${WORKER_BASE}?target=` + encodeURIComponent(targetUrl) + '&where=' + encodeURIComponent(where) + '&mode=prefix';
  try {
    // SECURITY: auth header added to Ahrefs proxy call
    const res = await fetch(workerUrl, { headers: authHeaders() });
    const data = await res.json();
    if (!data.backlinks) return [];
    return data.backlinks
      .filter(b => {
        if (studyPath === '/' || studyPath === '') return true;
        const targetPath = (b.url_to || '').replace(/^https?:\/\/(www\.)?/, 'https://').replace(/^https?:\/\/[^\/]+/, '');
        return targetPath.startsWith(studyPath);
      })
      .filter(b => {
        const d = b.url_from || '';
        return !d.includes('homezada.com') && !d.includes('mykukun.com') && !d.includes('nuxt.dev');
      })
      .map(b => {
        const covUrl = b.url_from || '';
        const ourUrl = b.url_to || '';
        const ourPath = ourUrl.replace(/^https?:\/\/[^\/]+/, '') || '/';
        const site = getSiteFromUrl(ourUrl);
        const matchedStudy = studies.slice().reverse().find(s => {
          try {
            const sPath = new URL(s.url).pathname.replace(/\/$/, '').replace(/#.*$/, '');
            return sPath.length > 1 && (ourPath === sPath || ourPath.startsWith(sPath + '/'));
          } catch(e) { return false; }
        });
        return {
          study: matchedStudy ? matchedStudy.name : name,
          outlet: getOutlet(covUrl),
          dr: Math.round(b.domain_rating_source || 0),
          covUrl,
          ourUrl,
          ourPath,
          site,
          firstSeen: b.first_seen ? b.first_seen.slice(0,10) : '',
          dateFound: b.first_seen ? b.first_seen.slice(0,10) : '',
          source: getSource(name, covUrl)
        };
      });
  } catch(e) {
    return [];
  }
}
async function fullRefresh() {
  if (isLoading) return;
  isLoading = true;
  const btn = document.getElementById('refresh-btn');
  btn.disabled = true;
  ahrefsRows = [];
  trackingStarted = true;
  await loadStudies();
  loadMuckrackSheet();
  if (!studies.length) {
    isLoading = false;
    btn.disabled = false;
    return;
  }
  const cutoff = getDateFrom();
  const total = studies.length;
  let done = 0;
  setProgress(0, `Fetching Ahrefs data for ${total} studies…`);
  document.getElementById('tbody-tracked').innerHTML = `<tr><td colspan="9" class="loading-cell">Fetching coverage data…</td></tr>`;
  document.getElementById('tbody-low').innerHTML = `<tr><td colspan="9" class="loading-cell">Fetching coverage data…</td></tr>`;
  const BATCH = 8;
  for (let i = 0; i < studies.length; i += BATCH) {
    const batch = studies.slice(i, i+BATCH);
    const results = await Promise.all(batch.map(s => fetchAhrefs(s.name, s.url, cutoff).catch(()=>[])));
    results.forEach(r => ahrefsRows.push(...r));
    done += batch.length;
    setProgress(Math.round((done/total)*100), `Fetching… ${done}/${total} studies — ${ahrefsRows.length} hits so far`);
    render();
  }
  const seen = new Set();
  ahrefsRows = ahrefsRows.filter(r => {
    const k = r.covUrl+'|'+r.ourUrl;
    if (seen.has(k)) return false;
    seen.add(k); return true;
  });
  const dr30 = ahrefsRows.filter(r=>r.dr>=30).length;
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
    if (!includeGeneral && (r.ourPath === '/' || r.ourPath === '')) return false;
    if (ignoreBlankStudy && (!r.study || r.study.trim() === '')) return false;
    if (r.covUrl && (r.covUrl.includes('prnewswire.com') || r.covUrl.includes('newswire.com'))) return false;
    if (r.outlet && r.outlet.toLowerCase().includes('pr newswire')) return false;
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
  if (!data.length) {
    tbody.innerHTML=`<tr><td colspan="9" class="empty">${trackingStarted ? 'No results match filters' : 'Click \'Start Tracking\' to view results'}</td></tr>`;
    return;
  }
  // SECURITY v3: safeHref() used on all URL fields to block javascript: URIs
  tbody.innerHTML = data.sort((a,b)=>b.dr-a.dr).map(r=>`
    <tr>
      <td title="${esc(r.study)}">${esc(r.study)}</td>
      <td title="${esc(r.outlet)}">${r.outlet?esc(r.outlet):'<span style="color:#bbb">—</span>'}</td>
      <td><span class="dr-badge ${drClass(r.dr)}">${r.dr}</span></td>
      <td title="${esc(r.covUrl)}"><a class="link" href="${safeHref(r.covUrl)}" target="_blank" rel="noopener noreferrer">${esc(shortUrl(r.covUrl))}</a></td>
      <td title="${esc(r.ourUrl||'')}"><a class="link" href="${safeHref(r.ourUrl||'')}" target="_blank" rel="noopener noreferrer">${esc(r.ourUrl ? (r.isMuckrack ? shortUrl(r.ourUrl) : r.ourPath) : '—')}</a></td>
      <td style="color:#999;font-size:12px;">${r.dateFound||''}</td>
      <td>${r.site ? '<span class="site-badge s-'+r.site+'">'+(SITE_LABELS[r.site]||r.site)+'</span>' : '<span style="color:#bbb;font-size:12px;">—</span>'}</td>
      <td>${srcBadge(r.source)}</td>
      <td><span class="src-badge ${r.isMuckrack ? 'src-muckrack' : 'src-ahrefs'}" style="font-size:11px;">${r.isMuckrack ? 'Muckrack' : 'Ahrefs'}</span></td>
    </tr>`).join('');
}
function renderTable(id, data, highDR) {
  const tbody = document.getElementById(id);
  if (!data.length) {
    tbody.innerHTML=`<tr><td colspan="9" class="empty">${trackingStarted ? 'No results match filters' : 'Click \'Start Tracking\' to view results'}</td></tr>`;
    return;
  }
  // SECURITY v3: safeHref() used on all URL fields to block javascript: URIs
  tbody.innerHTML = data.sort((a,b)=>b.dr-a.dr).map(r=>`
    <tr>
      <td title="${esc(r.study)}">${esc(r.study)}</td>
      <td title="${esc(r.outlet)}">${r.outlet?esc(r.outlet):'<span style="color:#bbb">—</span>'}</td>
      <td><span class="dr-badge ${highDR?drClass(r.dr):'dr-low'}">${r.dr}</span></td>
      <td title="${esc(r.covUrl)}"><a class="link" href="${safeHref(r.covUrl)}" target="_blank" rel="noopener noreferrer">${esc(shortUrl(r.covUrl))}</a></td>
      <td title="${esc(r.ourUrl)}"><a class="link" href="${safeHref(r.ourUrl)}" target="_blank" rel="noopener noreferrer">${esc(r.ourPath)}</a></td>
      <td style="color:#999;font-size:12px;">${r.dateFound}</td>
      <td><span class="site-badge s-${r.site}">${esc(SITE_LABELS[r.site]||r.site)}</span></td>
      <td>${srcBadge(r.source)}</td>
    </tr>`).join('');
}
function renderMuckrack() {
  const tbody2 = document.getElementById('tbody-muckrack-nolink');
  if (!trackingStarted) {
    tbody2.innerHTML='<tr><td colspan="5" class="empty">Click \'Start Tracking\' to view results</td></tr>';
  } else if (!muckrackNoLink.length) {
    tbody2.innerHTML='<tr><td colspan="5" class="empty">No unlinked mentions found for this date range — updates hourly</td></tr>';
  } else {
    tbody2.innerHTML = muckrackNoLink.sort((a,b)=>b.da-a.da).map(r=>`
      <tr>
        <td title="${esc(r.headline)}">${esc(r.headline)}</td>
        <td title="${esc(r.outlet)}">${esc(r.outlet)}</td>
        <td><span class="dr-badge ${drClass(r.da)}">${r.da}</span></td>
        <td style="color:#999;font-size:12px;">${esc(r.date||'')}</td>
        <td title="${esc(r.snippet||'')}" style="color:#999;font-size:12px;">${esc((r.snippet||'').slice(0,80))}</td>
      </tr>`).join('');
  }
}
function setTab(tab, btn) {
  document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  ['tracked','low','muckrack-nolink'].forEach(t=>{
    document.getElementById('panel-'+t).style.display=t===tab?'':'none';
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
    }))).filter(r=>r.dr>=drThreshold).sort((a,b)=>b.dr-a.dr);
    // SECURITY v4: csvSafe() prevents formula injection when pasting into Excel / Sheets
    text = combined.map(r=>[r.study, r.outlet, r.covUrl, r.ourUrl, r.dateFound, r.source].map(csvSafe).join('\t')).join('\n');
  } else if (tab==='low') {
    const all = filteredRows();
    const data = all.filter(r=>r.dr<30);
    text = data.sort((a,b)=>b.dr-a.dr)
      .map(r=>[r.study, r.outlet, r.covUrl, r.ourUrl, r.dateFound, r.source].map(csvSafe).join('\t'))
      .join('\n');
  } else if (tab==='muckrack-nolink') {
    text = muckrackNoLink.map(r=>[r.headline, r.outlet, '', '', r.date, ''].map(csvSafe).join('\t')).join('\n');
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
  const lines = text.trim().split(/\r?\n/).slice(1);
  const year = new Date().getFullYear();
  const firstLine = lines[0] || '';
  const firstCols = (firstLine.match(/(".*?"|[^,]+|(?<=,)(?=,)|^(?=,)|(?<=,)$)/g) || firstLine.split(',')).length;
  const newFormat = firstCols >= 7;
  for (const line of lines) {
    const cols = line.match(/(".*?"|[^,]+|(?<=,)(?=,)|^(?=,)|(?<=,)$)/g) || line.split(',');
    const clean = cols.map(c => c.replace(/^"|"$/g,'').trim());
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
      fetch(`${WORKER_BASE}/sheets/muckrack-link`,    { headers: authHeaders() }),
      fetch(`${WORKER_BASE}/sheets/muckrack-nolink`,  { headers: authHeaders() })
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
