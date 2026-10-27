/* Campus Talks & Events: static, client-side decrypted. No build step. */
(() => {
  'use strict';
  const TZ = 'Asia/Kolkata';
  const LS = { pass: 'ce.passphrase', picks: 'ce.picks', picks2: 'ce.picks.v2', last: 'ce.lastVisit', ui: 'ce.ui',
    token: 'ce.sync.token', dirty: 'ce.sync.dirty', lastSync: 'ce.sync.last' };
  const SYNC = { owner: 'nishron03', repo: 'campus-events-picks', path: 'picks.enc.json' };
  const S = window.CESync;
  const TALK_CATS = [['all', 'All'], ['core', 'Core research'], ['physics', 'Physics'], ['other', 'Other'], ['social', 'Social']];
  const EVENT_CATS = [['all', 'All'], ['event', 'Events'], ['opportunity', 'Opportunities']];
  const CAT_LABEL = { core: 'Core research', physics: 'Physics', other: 'Other', social: 'Social', event: 'Event', opportunity: 'Opportunity' };

  const $ = (s) => document.querySelector(s);
  let DATA = null, prevVisit = null, expanded = new Set();
  let ui = Object.assign({ tab: 'talks', talkCat: 'all', eventCat: 'all', hidePast: true }, readJSON(LS.ui, {}));
  let PASS = null; // passphrase in memory after unlock (needed to encrypt synced picks)
  let pickState = loadPicks(), picks = S.effective(pickState);

  function readJSON(k, d) { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } }
  function saveUI() { localStorage.setItem(LS.ui, JSON.stringify(ui)); }

  /* ---------- crypto (mirrors update.py) ---------- */
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  async function decrypt(env, passphrase) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt: b64(env.salt), iterations: env.iter },
      base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(env.iv) }, key, b64(env.ct));
    return JSON.parse(new TextDecoder().decode(pt));
  }
  async function fetchEnvelope() {
    const r = await fetch('data.enc.json', { cache: 'no-cache' });
    if (!r.ok) throw new Error('Could not load data (' + r.status + ')');
    return r.json();
  }

  /* ---------- time helpers (all display in IST) ---------- */
  const isDateOnly = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s);
  function toDate(s, endOfDay) {
    if (!s) return null;
    if (isDateOnly(s)) return new Date(s + (endOfDay ? 'T23:59:59+05:30' : 'T00:00:00+05:30'));
    const d = new Date(s); return isNaN(d) ? null : d;
  }
  const fmtDay = new Intl.DateTimeFormat('en-IN', { timeZone: TZ, weekday: 'short', day: 'numeric', month: 'short' });
  const fmtTime = new Intl.DateTimeFormat('en-IN', { timeZone: TZ, hour: 'numeric', minute: '2-digit', hour12: true });
  const fmtFull = new Intl.DateTimeFormat('en-IN', { timeZone: TZ, day: 'numeric', month: 'short', year: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true });
  const istKey = (d) => new Intl.DateTimeFormat('en-CA', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
  function dayDiff(d) { // calendar days from today (IST) to d (IST)
    const a = new Date(istKey(new Date()) + 'T00:00:00Z'), b = new Date(istKey(d) + 'T00:00:00Z');
    return Math.round((b - a) / 86400000);
  }
  function when(start, end) {
    const s = toDate(start); if (!s) return null;
    let out = fmtDay.format(s) + (isDateOnly(start) ? '' : ', ' + fmtTime.format(s));
    const e = toDate(end);
    if (e) {
      if (istKey(e) === istKey(s)) { if (!isDateOnly(end)) out += ' – ' + fmtTime.format(e); }
      else out += ' → ' + fmtDay.format(e) + (isDateOnly(end) ? '' : ', ' + fmtTime.format(e));
    }
    return out + ' IST';
  }
  function deadlineInfo(it) {
    const d = toDate(it.deadline, true); if (!d) return null;
    const now = new Date();
    if (d < now) return { cls: 'closed', label: 'closed', rank: 3, t: d };
    const n = dayDiff(d);
    if (n <= 0) return { cls: 'today', label: 'due today', rank: 0, t: d };
    if (n === 1) return { cls: 'soon', label: 'due tomorrow', rank: 0, t: d };
    return { cls: n <= 3 ? 'soon' : '', label: `in ${n} days`, rank: 0, t: d };
  }
  function isPast(it) {
    const now = new Date();
    const end = toDate(it.end, true) || toDate(it.start, true);
    const dl = toDate(it.deadline, true);
    if (end && end >= now) return false;
    if (dl && dl >= now) return false;
    return !!(end || dl);
  }

  /* ---------- picks / new ---------- */
  // ce.picks.v2 = {id: {pick, updated_at}} incl. tombstones (pick: null). ce.picks (plain {id: pick}) is kept
  // as a mirror so an older cached app version still sees the right picks.
  function loadPicks() {
    const v2 = readJSON(LS.picks2, null);
    if (v2 && typeof v2 === 'object') {
      const r = S.reconcileLegacy(S.cleanState(v2), readJSON(LS.picks, {}));
      if (r.changed) { localStorage.setItem(LS.picks2, JSON.stringify(r.state)); localStorage.setItem(LS.dirty, '1'); }
      return r.state;
    }
    const migrated = S.fromLegacy(readJSON(LS.picks, {}));
    localStorage.setItem(LS.picks2, JSON.stringify(migrated));
    if (Object.keys(migrated).length) localStorage.setItem(LS.dirty, '1');
    return migrated;
  }
  function savePicks(state) {
    pickState = state; picks = S.effective(state);
    localStorage.setItem(LS.picks2, JSON.stringify(state));
    localStorage.setItem(LS.picks, JSON.stringify(picks));
  }
  function setPick(id, v) {
    savePicks(S.setPick(S.cleanState(readJSON(LS.picks2, pickState)), id, v));
    localStorage.setItem(LS.dirty, '1');
    render(); sync.soon();
  }
  const isNew = (it) => prevVisit && it.added_at && new Date(it.added_at) > new Date(prevVisit);

  /* ---------- rendering ---------- */
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const safeUrl = (u) => (typeof u === 'string' && /^https?:\/\//i.test(u.trim())) ? u.trim() : null;
  function matches(it, q) {
    if (!q) return true;
    const hay = [it.title, it.speaker, it.affiliation, it.organizer, it.venue, it.summary, it.speaker_bio].join(' ').toLowerCase();
    return q.split(/\s+/).every((w) => hay.includes(w));
  }
  function sortTalks(a, b) {
    const pa = isPast(a), pb = isPast(b);
    if (pa !== pb) return pa ? 1 : -1;
    const sa = toDate(a.start), sb = toDate(b.start);
    if (!sa || !sb) return sa ? -1 : sb ? 1 : 0;
    return pa ? sb - sa : sa - sb;
  }
  function sortEvents(a, b) {
    const da = deadlineInfo(a), db = deadlineInfo(b);
    const ra = da ? da.rank : (isPast(a) ? 4 : 1), rb = db ? db.rank : (isPast(b) ? 4 : 1);
    if (ra !== rb) return ra - rb;
    if (da && db && ra === 0) return da.t - db.t;
    if (da && db) return db.t - da.t; // closed: most recently closed first
    const sa = toDate(a.start), sb = toDate(b.start);
    if (sa && sb) return sa - sb;
    return sa ? -1 : sb ? 1 : 0;
  }
  function cardHTML(it) {
    const open = expanded.has(it.id), pick = picks[it.id], dl = deadlineInfo(it), past = isPast(it);
    const badges = [`<span class="badge cat">${esc(CAT_LABEL[it.category] || it.category)}</span>`];
    if (isNew(it)) badges.push('<span class="badge new">new</span>');
    if (dl) badges.push(`<span class="badge ${dl.cls}">${esc(dl.label)}</span>`);
    else if (past) badges.push('<span class="badge closed">past</span>');
    const meta = [];
    const w = when(it.start, it.end); if (w) meta.push('🗓 ' + w);
    if (it.venue) meta.push('📍 ' + it.venue);
    if (it.speaker) meta.push('🎤 ' + it.speaker + (it.affiliation ? ' · ' + it.affiliation : ''));
    else if (it.kind === 'event' && it.organizer) meta.push(it.organizer);
    if (it.deadline) { const d = toDate(it.deadline, true); meta.push('⏳ Deadline ' + (isDateOnly(it.deadline) ? fmtDay.format(d) : fmtFull.format(d)) + ' IST'); }
    let details = '';
    if (open) {
      const rows = [['Speaker', it.speaker], ['Affiliation', it.affiliation], ['About speaker', it.speaker_bio], ['Organizer', it.organizer]]
        .filter(([, v]) => v).map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join('');
      const links = [['Email', it.email_link], ['Register / apply', it.registration_link], ['Join online', it.online_link]]
        .map(([k, u]) => [k, safeUrl(u)]).filter(([, u]) => u)
        .map(([k, u]) => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${k} ↗</a>`).join('');
      details = `<div class="details">${it.summary ? `<p>${esc(it.summary)}</p>` : ''}${rows ? `<dl>${rows}</dl>` : ''}<div class="links">${links}</div></div>`;
    }
    const pk = (v, label) => `<button class="pick" data-id="${esc(it.id)}" data-v="${v}" aria-pressed="${pick === v}">${label}</button>`;
    return `<article class="card${isNew(it) ? ' is-new' : ''}${pick === 'skip' ? ' skip' : ''}${past ? ' past' : ''}" style="--cat: var(--${esc(it.category)})">
      <button class="card-head" data-toggle="${esc(it.id)}" aria-expanded="${open}">
        <div class="badges">${badges.join('')}</div>
        <h2>${esc(it.title)}</h2>
        <div class="meta">${meta.map((m) => `<span>${esc(m)}</span>`).join('')}</div>
      </button>${details}
      <div class="picks">${pk('todo', 'To-do')}${pk('maybe', 'Maybe')}${pk('skip', 'Skip')}</div>
    </article>`;
  }
  function chipsHTML(defs, active, items, key) {
    return defs.map(([v, label]) => {
      const n = v === 'all' ? items.length : items.filter((x) => x.category === v).length;
      return `<button class="chip${active === v ? ' active' : ''}" data-chip="${key}" data-v="${v}">${label}<span class="n">${n}</span></button>`;
    }).join('');
  }
  function render() {
    if (!DATA) return;
    const q = $('#search').value.trim().toLowerCase();
    const visible = (it) => matches(it, q) && !(ui.hidePast && isPast(it));
    document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === ui.tab));
    const todo = DATA.items.filter((x) => picks[x.id] === 'todo');
    $('#mine-count').textContent = todo.length || '';
    let html = '', chips = '';
    const skipLast = (arr) => [...arr.filter((x) => picks[x.id] !== 'skip'), ...arr.filter((x) => picks[x.id] === 'skip')];
    if (ui.tab === 'talks') {
      const base = DATA.items.filter((x) => x.kind === 'talk' && visible(x));
      chips = chipsHTML(TALK_CATS, ui.talkCat, base, 'talkCat');
      const list = skipLast(base.filter((x) => ui.talkCat === 'all' || x.category === ui.talkCat).sort(sortTalks));
      html = list.map(cardHTML).join('');
    } else if (ui.tab === 'events') {
      const base = DATA.items.filter((x) => x.kind === 'event' && visible(x));
      chips = chipsHTML(EVENT_CATS, ui.eventCat, base, 'eventCat');
      const list = skipLast(base.filter((x) => ui.eventCat === 'all' || x.category === ui.eventCat).sort(sortEvents));
      html = list.map(cardHTML).join('');
    } else {
      const byTime = (a, b) => (toDate(a.start) || toDate(a.deadline, true) || 8.64e15) - (toDate(b.start) || toDate(b.deadline, true) || 8.64e15);
      const t = todo.filter(visible).sort(byTime);
      const m = DATA.items.filter((x) => picks[x.id] === 'maybe' && visible(x)).sort(byTime);
      html = (t.length ? '<h3 class="section-title">To-do</h3>' + t.map(cardHTML).join('') : '')
        + (m.length ? '<h3 class="section-title">Maybe</h3>' + m.map(cardHTML).join('') : '');
      if (!t.length && !m.length) html = '<p class="empty">Nothing here yet. Tap “To-do” on a talk or event to add it.</p>';
    }
    $('#chips').innerHTML = chips;
    $('#chips').hidden = !chips;
    $('#list').innerHTML = html || '<p class="empty">No matching items.</p>';
  }

  /* ---------- sync (optional; local-only without a token) ---------- */
  const sync = (() => {
    let timer = null, running = null, again = false, lastRun = 0, retryMs = 0, state = 'local', detail = '';
    const token = () => localStorage.getItem(LS.token);
    const dirty = () => localStorage.getItem(LS.dirty) === '1';
    const ago = (t) => { const m = Math.round((Date.now() - t) / 60000); return m < 1 ? 'just now' : m < 60 ? m + ' min ago' : fmtFull.format(new Date(t)) + ' IST'; };
    const LABEL = { local: 'This device', ok: 'Synced', busy: 'Syncing…', pending: 'Not synced yet', offline: 'Offline', error: 'Sync paused' };
    function show(s, d) {
      state = s; if (d !== undefined) detail = d;
      const pill = $('#sync-pill'); if (!pill) return;
      pill.dataset.state = s; $('#sync-label').textContent = LABEL[s];
      const last = +localStorage.getItem(LS.lastSync) || 0;
      const line = s === 'local' ? 'Not connected. Picks are saved on this device only.'
        : s === 'ok' ? 'Synced ' + ago(last) + '.'
        : s === 'busy' ? 'Syncing…'
        : s === 'offline' ? 'Offline. Changes are saved here and will sync when you are back online.'
        : s === 'pending' ? 'Changes saved here, syncing shortly.'
        : (detail || 'Sync failed.') + (last ? ' Last synced ' + ago(last) + '.' : '');
      pill.title = line;
      $('#sync-status').dataset.state = s; $('#sync-detail').textContent = line;
      $('#sync-connect').hidden = !!token(); $('#sync-connected').hidden = !token();
      $('#foot-note').textContent = token() ? 'Picks sync across your devices (encrypted).' : 'Picks are stored on this device only.';
    }
    function idle() {
      if (!token()) return show('local');
      if (!navigator.onLine) return show('offline');
      show(dirty() ? 'pending' : 'ok');
    }
    async function run(tok) {
      tok = tok || token();
      if (!tok || !PASS) return idle();
      if (!navigator.onLine) return show('offline');
      if (running) { again = true; return running; }
      clearTimeout(timer); timer = null; lastRun = Date.now();
      show('busy');
      running = (async () => {
        const api = S.client({ token: tok, ...SYNC });
        const wasDirty = dirty(); localStorage.removeItem(LS.dirty);
        try {
          const r = await S.syncOnce({ api, passphrase: PASS, getLocal: () => S.cleanState(readJSON(LS.picks2, pickState)), device: deviceName() });
          // merge again: keeps any pick made while the request was in flight
          const latest = S.cleanState(readJSON(LS.picks2, pickState)), merged = S.merge(latest, r.state);
          if (!S.sameState(merged, r.state)) localStorage.setItem(LS.dirty, '1'); // edits made mid-flight
          if (!S.sameState(merged, pickState)) { savePicks(merged); render(); } else savePicks(merged);
          localStorage.setItem(LS.lastSync, String(Date.now())); retryMs = 0;
          return { ok: true };
        } catch (e) {
          if (wasDirty || dirty()) localStorage.setItem(LS.dirty, '1');
          const kind = e && e.kind;
          if (kind === 'network') {
            retryMs = Math.min(retryMs ? retryMs * 2 : 30000, 300000);
            show(navigator.onLine ? 'error' : 'offline', "Couldn't reach GitHub, will retry.");
            timer = setTimeout(() => run(), retryMs);
          } else show('error', (e && e.message) || 'Sync failed.');
          return { ok: false, error: e };
        } finally {
          running = null;
          if (state === 'busy') idle();
          if (again || (dirty() && token() && navigator.onLine && state !== 'error')) { again = false; soon(); }
        }
      })();
      return running;
    }
    function soon(ms = 1200) {
      if (!token()) return idle();
      if (state !== 'busy') show(navigator.onLine ? 'pending' : 'offline');
      clearTimeout(timer); timer = setTimeout(() => run(), ms);
    }
    function deviceName() {
      const ua = navigator.userAgent;
      return /Android/i.test(ua) ? 'Android' : /Mac OS X/i.test(ua) ? 'Mac' : /Linux/i.test(ua) ? 'Linux' : 'browser';
    }
    function bindUI() {
      const dlg = $('#sync-dlg');
      const open = () => { idle(); $('#sync-error').hidden = true; dlg.showModal ? dlg.showModal() : dlg.setAttribute('open', ''); };
      $('#sync-pill').addEventListener('click', open);
      $('#foot-note').addEventListener('click', open);
      $('#sync-close').addEventListener('click', () => dlg.close ? dlg.close() : dlg.removeAttribute('open'));
      $('#sync-connect').addEventListener('submit', async (e) => {
        e.preventDefault();
        const tok = $('#sync-token').value.trim(), btn = $('#sync-save'), err = $('#sync-error');
        err.hidden = true; if (!tok) return;
        btn.disabled = true; btn.textContent = 'Connecting…';
        localStorage.setItem(LS.dirty, '1'); // first sync uploads everything this device has
        const r = await run(tok);
        btn.disabled = false; btn.textContent = 'Connect';
        if (r && !r.ok && r.error && r.error.kind !== 'network') {
          err.textContent = r.error.message; err.hidden = false; idle(); return;
        }
        localStorage.setItem(LS.token, tok); $('#sync-token').value = '';
        if (r && !r.ok) { err.textContent = "Saved. Couldn't reach GitHub yet; will sync when online."; err.hidden = false; }
        idle(); if (dirty()) soon();
      });
      $('#sync-now').addEventListener('click', () => run());
      $('#sync-disconnect').addEventListener('click', () => {
        localStorage.removeItem(LS.token); localStorage.removeItem(LS.lastSync); clearTimeout(timer); idle();
      });
      document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') onFocus(); });
      window.addEventListener('focus', onFocus);
      window.addEventListener('online', () => soon(300));
      window.addEventListener('offline', () => idle());
      window.addEventListener('storage', (e) => { // another tab changed picks
        if (e.key === LS.picks2) { pickState = S.cleanState(readJSON(LS.picks2, {})); picks = S.effective(pickState); render(); }
        if (e.key === LS.token) idle();
      });
    }
    function onFocus() { if (token() && Date.now() - lastRun > 5000) run(); }
    return { run, soon, idle, bindUI };
  })();

  /* ---------- events ---------- */
  function bind() {
    document.querySelector('.tabs').addEventListener('click', (e) => {
      const t = e.target.closest('.tab'); if (!t) return;
      ui.tab = t.dataset.tab; saveUI(); render(); window.scrollTo({ top: 0 });
    });
    $('#chips').addEventListener('click', (e) => {
      const c = e.target.closest('.chip'); if (!c) return;
      ui[c.dataset.chip] = c.dataset.v; saveUI(); render();
    });
    $('#list').addEventListener('click', (e) => {
      const p = e.target.closest('.pick');
      if (p) { setPick(p.dataset.id, p.dataset.v); return; }
      const h = e.target.closest('[data-toggle]');
      if (h) { const id = h.dataset.toggle; expanded.has(id) ? expanded.delete(id) : expanded.add(id); render(); }
    });
    $('#search').addEventListener('input', render);
    $('#hide-past').checked = ui.hidePast;
    $('#hide-past').addEventListener('change', (e) => { ui.hidePast = e.target.checked; saveUI(); render(); });
    $('#lock-btn').addEventListener('click', () => { localStorage.removeItem(LS.pass); location.reload(); });
    sync.bindUI();
  }

  function onUnlocked(data) {
    DATA = data;
    // "new since last visit": the previous visit time is fixed for this browser session.
    prevVisit = sessionStorage.getItem(LS.last) ?? localStorage.getItem(LS.last);
    sessionStorage.setItem(LS.last, prevVisit ?? '');
    if (!prevVisit) prevVisit = null;
    localStorage.setItem(LS.last, new Date().toISOString());
    const g = toDate(data.generated_at);
    $('#updated').textContent = g ? 'Last updated ' + fmtFull.format(g) + ' IST · ' + data.items.length + ' items' : '';
    $('#lock').hidden = true; $('#app').hidden = false;
    bind(); render();
    sync.idle(); sync.run();
  }

  async function start() {
    let env;
    try { env = await fetchEnvelope(); } catch (e) { showLock(e.message); return; }
    const saved = localStorage.getItem(LS.pass);
    if (saved) {
      try { const d = await decrypt(env, saved); PASS = saved; onUnlocked(d); return; } catch { localStorage.removeItem(LS.pass); }
    }
    showLock();
    $('#lock-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = e.target.querySelector('button'), pass = $('#pass').value.trim();
      btn.disabled = true; btn.textContent = 'Unlocking…'; $('#lock-error').hidden = true;
      try {
        const data = await decrypt(env, pass);
        if ($('#remember').checked) localStorage.setItem(LS.pass, pass);
        PASS = pass; onUnlocked(data);
      } catch {
        $('#lock-error').textContent = 'That passphrase did not work.'; $('#lock-error').hidden = false;
      } finally { btn.disabled = false; btn.textContent = 'Unlock'; }
    });
  }
  function showLock(msg) {
    $('#lock').hidden = false;
    if (msg) { $('#lock-error').textContent = msg; $('#lock-error').hidden = false; }
  }

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
  start();
})();
