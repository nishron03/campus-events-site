/* Picks sync core: per-item last-write-wins merge, AES-GCM envelope, GitHub Contents API client.
 * Plain script (window.CESync) and CommonJS (require) so tests/ can run the exact same code in Node. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.CESync = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  const PICKS = ['todo', 'maybe', 'skip'];
  const ITER = 310000;
  const enc = new TextEncoder(), dec = new TextDecoder();

  /* ---------- base64 (binary-safe, works in browsers and Node >= 16) ---------- */
  function toB64(bytes) {
    let s = ''; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  }
  const fromB64 = (s) => Uint8Array.from(atob(String(s).replace(/\s+/g, '')), (c) => c.charCodeAt(0));

  /* ---------- picks state ----------
   * state = { [itemId]: { pick: 'todo'|'maybe'|'skip'|null, updated_at: epoch ms } }
   * pick === null is a tombstone (a cleared pick), kept so the clear wins over older remote values. */
  function cleanEntry(e) {
    if (!e || typeof e !== 'object') return null;
    const t = Number(e.updated_at);
    if (!Number.isFinite(t) || t < 0) return null;
    const pick = PICKS.includes(e.pick) ? e.pick : null;
    if (e.pick != null && pick === null) return null; // unknown value: ignore rather than turn into a clear
    return { pick, updated_at: t };
  }
  function cleanState(s) {
    const out = {};
    if (s && typeof s === 'object') for (const id of Object.keys(s)) { const e = cleanEntry(s[id]); if (e) out[id] = e; }
    return out;
  }
  const rank = (p) => (p == null ? 0 : PICKS.length - PICKS.indexOf(p)); // deterministic tie-break: todo > maybe > skip > cleared
  function newer(a, b) {
    if (!a) return b; if (!b) return a;
    if (a.updated_at !== b.updated_at) return a.updated_at > b.updated_at ? a : b;
    return rank(a.pick) >= rank(b.pick) ? a : b;
  }
  function merge(a, b) {
    a = cleanState(a); b = cleanState(b);
    const out = {};
    for (const id of new Set([...Object.keys(a), ...Object.keys(b)])) out[id] = { ...newer(a[id], b[id]) };
    return out;
  }
  /** Apply a user action. Same pick again clears it (toggle), like the original app. Timestamps never go backwards. */
  function setPick(state, id, pick, now = Date.now()) {
    const cur = state[id];
    const next = cur && cur.pick === pick ? null : (PICKS.includes(pick) ? pick : null);
    const t = Math.max(now, cur ? cur.updated_at + 1 : 0);
    return { ...state, [id]: { pick: next, updated_at: t } };
  }
  /** Flatten to the legacy {id: pick} map the UI (and old app versions) use. */
  function effective(state) {
    const out = {};
    for (const [id, e] of Object.entries(state)) if (e && e.pick) out[id] = e.pick;
    return out;
  }
  /** Legacy localStorage `ce.picks` ({id: pick}) → state. Migrated entries get a tiny timestamp so any real,
   *  timestamped change made on another device wins, while picks unique to this device are kept. */
  function fromLegacy(legacy, t = 1) {
    const out = {};
    if (legacy && typeof legacy === 'object') for (const [id, p] of Object.entries(legacy)) if (PICKS.includes(p)) out[id] = { pick: p, updated_at: t };
    return out;
  }
  /** ce.picks is kept as a mirror of effective(state). If it differs, an older app version (e.g. a stale cached tab)
   *  changed it after us: apply those differences as fresh edits so nothing it recorded is lost. */
  function reconcileLegacy(state, legacy, now = Date.now()) {
    const eff = effective(state), out = { ...state };
    let changed = false;
    legacy = legacy && typeof legacy === 'object' ? legacy : {};
    for (const [id, p] of Object.entries(legacy)) {
      if (PICKS.includes(p) && eff[id] !== p) { out[id] = { pick: p, updated_at: Math.max(now, (state[id] ? state[id].updated_at : 0) + 1) }; changed = true; }
    }
    for (const id of Object.keys(eff)) {
      if (!(id in legacy)) { out[id] = { pick: null, updated_at: Math.max(now, state[id].updated_at + 1) }; changed = true; }
    }
    return { state: out, changed };
  }
  function canonical(state) {
    const s = cleanState(state);
    return JSON.stringify(Object.keys(s).sort().map((k) => [k, s[k].pick, s[k].updated_at]));
  }
  const sameState = (a, b) => canonical(a) === canonical(b);

  /* ---------- encryption (same envelope as data.enc.json / update.py) ---------- */
  const keyCache = new Map();
  async function deriveKey(passphrase, salt, iter) {
    const k = iter + ':' + toB64(salt) + ':' + passphrase;
    if (!keyCache.has(k)) {
      keyCache.set(k, (async () => {
        const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
        return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter },
          base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
      })().catch((e) => { keyCache.delete(k); throw e; }));
    }
    return keyCache.get(k);
  }
  /** Encrypt obj. Reuses `salt` (base64) if given so the PBKDF2 key can be cached; the IV is always fresh. */
  async function encryptJSON(obj, passphrase, salt) {
    const s = salt ? fromB64(salt) : crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(passphrase, s, ITER);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj))));
    return { v: 1, alg: 'AES-256-GCM', kdf: 'PBKDF2-SHA256', iter: ITER, salt: toB64(s), iv: toB64(iv), ct: toB64(ct) };
  }
  async function decryptJSON(env, passphrase) {
    if (!env || env.alg !== 'AES-256-GCM' || !env.salt || !env.iv || !env.ct) throw new Error('bad envelope');
    const key = await deriveKey(passphrase, fromB64(env.salt), env.iter || ITER);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(env.iv) }, key, fromB64(env.ct));
    return JSON.parse(dec.decode(pt));
  }

  /* ---------- GitHub Contents API ---------- */
  class SyncError extends Error { constructor(kind, msg, status) { super(msg); this.kind = kind; this.status = status; } }
  function client({ token, owner, repo, path, branch, fetchImpl }) {
    const f = fetchImpl || ((...a) => fetch(...a));
    const url = `https://api.github.com/repos/${owner}/${repo}/contents/${path.split('/').map(encodeURIComponent).join('/')}`;
    const headers = { Accept: 'application/vnd.github+json', Authorization: 'Bearer ' + token, 'X-GitHub-Api-Version': '2022-11-28' };
    async function call(method, u, body) {
      let r;
      try { r = await f(u, { method, headers: body ? { ...headers, 'Content-Type': 'application/json' } : headers, body: body ? JSON.stringify(body) : undefined, cache: 'no-store' }); }
      catch (e) { throw new SyncError('network', 'Network error'); }
      return r;
    }
    function fail(r, what) {
      if (r.status === 401) return new SyncError('auth', 'Token rejected (expired or revoked?)', 401);
      if (r.status === 403 || r.status === 404) return new SyncError('access', `Token can't ${what} ${owner}/${repo}`, r.status);
      return new SyncError('http', `GitHub ${what} failed (${r.status})`, r.status);
    }
    return {
      /** → {sha, env} or null when the file does not exist yet. */
      async get() {
        const r = await call('GET', url + (branch ? '?ref=' + encodeURIComponent(branch) : ''));
        if (r.status === 404) {
          // file missing vs. repo not visible to the token: ask about the repo once
          const rr = await call('GET', `https://api.github.com/repos/${owner}/${repo}`);
          if (rr.ok) return null;
          throw fail(rr, 'read');
        }
        if (!r.ok) throw fail(r, 'read');
        const j = await r.json();
        let env;
        try { env = JSON.parse(dec.decode(fromB64(j.content))); } catch { throw new SyncError('format', 'Synced file is not readable'); }
        return { sha: j.sha, env };
      },
      /** → new sha. Throws SyncError kind 'conflict' when sha is stale (409/422). */
      async put(env, sha, message) {
        const body = { message: message || 'Update picks', content: toB64(enc.encode(JSON.stringify(env) + '\n')) };
        if (sha) body.sha = sha; if (branch) body.branch = branch;
        const r = await call('PUT', url, body);
        if (r.status === 409 || r.status === 422) throw new SyncError('conflict', 'Changed elsewhere', r.status);
        if (!r.ok) throw fail(r, 'write');
        return (await r.json()).content.sha;
      },
      async remove(sha, message) {
        const body = { message: message || 'Remove file', sha }; if (branch) body.branch = branch;
        const r = await call('DELETE', url, body);
        if (!r.ok) throw fail(r, 'delete');
      },
    };
  }

  /**
   * One sync round: read remote, merge with local, write back if remote differs. Retries on sha conflicts.
   * getLocal() is called fresh on every attempt so picks made while a sync is in flight are never lost.
   * Returns { state, sha, wrote, attempts }. The caller saves `state` locally (merge it with any newer local edits).
   */
  async function syncOnce({ api, passphrase, getLocal, device, maxAttempts = 5 }) {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const remote = await api.get();
      let remoteState = {}, salt;
      if (remote) {
        let doc;
        try { doc = await decryptJSON(remote.env, passphrase); }
        catch { throw new SyncError('decrypt', "Can't decrypt synced picks (passphrase changed?)"); }
        remoteState = cleanState(doc && doc.items);
        salt = remote.env.salt;
      }
      const merged = merge(getLocal(), remoteState);
      if (remote && sameState(merged, remoteState)) return { state: merged, sha: remote.sha, wrote: false, attempts: attempt };
      const env = await encryptJSON({ v: 2, updated_at: new Date().toISOString(), device: device || null, items: merged }, passphrase, salt);
      try {
        const sha = await api.put(env, remote && remote.sha, `Update picks${device ? ' from ' + device : ''}`);
        return { state: merged, sha, wrote: true, attempts: attempt };
      } catch (e) {
        if (e.kind !== 'conflict' || attempt === maxAttempts) throw e;
        await new Promise((r) => setTimeout(r, 150 * attempt + Math.random() * 250));
      }
    }
  }

  return { PICKS, merge, setPick, effective, fromLegacy, reconcileLegacy, cleanState, sameState, encryptJSON, decryptJSON, client, syncOnce, SyncError, toB64, fromB64 };
});
