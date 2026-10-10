import express from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const MAL_CLIENT_ID = process.env.MAL_CLIENT_ID || '';
const MAL_CLIENT_SECRET = process.env.MAL_CLIENT_SECRET || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const BASE_URL = (process.env.BASE_URL || '').replace(/\/$/, '');
const COOKIE = 'mediahub_session';

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '32kb' }));
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', maxAge: '1h' }));

function ready() { return Boolean(MAL_CLIENT_ID && SESSION_SECRET.length >= 32 && BASE_URL.startsWith('https://')); }
function b64url(buf) { return Buffer.from(buf).toString('base64url'); }
function seal(data) {
  const key = crypto.createHash('sha256').update(SESSION_SECRET).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(data), 'utf8'), cipher.final()]);
  return [b64url(iv), b64url(cipher.getAuthTag()), b64url(encrypted)].join('.');
}
function unseal(value) {
  if (!value || !SESSION_SECRET) return null;
  try {
    const [iv, tag, body] = value.split('.');
    const key = crypto.createHash('sha256').update(SESSION_SECRET).digest();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
    decipher.setAuthTag(Buffer.from(tag, 'base64url'));
    return JSON.parse(Buffer.concat([decipher.update(Buffer.from(body, 'base64url')), decipher.final()]).toString('utf8'));
  } catch { return null; }
}
function readCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const ix = part.indexOf('=');
    if (ix >= 0 && part.slice(0, ix).trim() === name) return decodeURIComponent(part.slice(ix + 1).trim());
  }
  return null;
}
function setSession(res, data, maxAge = 60 * 60 * 24 * 30) {
  res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(seal(data))}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`);
}
function clearSession(res) { res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`); }
function getSession(req) { return unseal(readCookie(req, COOKIE)); }
function requireReady(req, res, next) {
  if (!ready()) return res.status(503).json({ error: 'not_configured', message: 'Configure MAL_CLIENT_ID, SESSION_SECRET and BASE_URL in the hosting environment first.' });
  next();
}
async function malFetch(url, token, options = {}) {
  const response = await fetch(url, { ...options, headers: { Authorization: `Bearer ${token}`, 'X-MAL-CLIENT-ID': MAL_CLIENT_ID, Accept: 'application/json', ...(options.headers || {}) } });
  const text = await response.text();
  let body; try { body = text ? JSON.parse(text) : {}; } catch { body = { message: text.slice(0, 300) }; }
  if (!response.ok) {
    const error = new Error(body.message || `MyAnimeList returned HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return body;
}
async function refreshIfNeeded(session) {
  if (!session?.tokens?.refresh_token) return session;
  if (session.tokens.expires_at && Date.now() < session.tokens.expires_at - 60_000) return session;
  const params = new URLSearchParams({ grant_type: 'refresh_token', client_id: MAL_CLIENT_ID, refresh_token: session.tokens.refresh_token });
  if (MAL_CLIENT_SECRET) params.set('client_secret', MAL_CLIENT_SECRET);
  const r = await fetch('https://myanimelist.net/v1/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.message || 'Token refresh failed. Please connect MAL again.');
  session.tokens = { ...data, refresh_token: data.refresh_token || session.tokens.refresh_token, expires_at: Date.now() + Number(data.expires_in || 3600) * 1000 };
  return session;
}

app.get('/health', (_req, res) => res.json({ ok: true, configured: ready() }));
app.get('/auth/mal', requireReady, (req, res) => {
  // MyAnimeList's current OAuth implementation is commonly documented with PKCE plain mode.
  // Keep the challenge equal to the verifier for compatibility with MAL's documented flow.
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = verifier;
  const state = b64url(crypto.randomBytes(24));
  setSession(res, { oauth: { verifier, state, created_at: Date.now() } }, 600);
  const q = new URLSearchParams({ response_type: 'code', client_id: MAL_CLIENT_ID, redirect_uri: `${BASE_URL}/auth/callback`, code_challenge: challenge, state });
  res.redirect(`https://myanimelist.net/v1/oauth2/authorize?${q}`);
});
app.get('/auth/callback', requireReady, async (req, res) => {
  try {
    const previous = getSession(req);
    if (req.query.error) return res.status(400).send('MyAnimeList authorization was cancelled or denied. You can return to the MediaHub homepage.');
    if (!req.query.code || !req.query.state || !previous?.oauth || previous.oauth.state !== req.query.state || Date.now() - previous.oauth.created_at > 10 * 60 * 1000) {
      clearSession(res); return res.status(400).send('OAuth state is invalid or expired. Please return to MediaHub and try again.');
    }
    const params = new URLSearchParams({ grant_type: 'authorization_code', client_id: MAL_CLIENT_ID, code: String(req.query.code), redirect_uri: `${BASE_URL}/auth/callback`, code_verifier: previous.oauth.verifier });
    if (MAL_CLIENT_SECRET) params.set('client_secret', MAL_CLIENT_SECRET);
    const tokenResponse = await fetch('https://myanimelist.net/v1/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: params });
    const tokens = await tokenResponse.json().catch(() => ({}));
    if (!tokenResponse.ok) { console.error('MAL token exchange failed:', tokenResponse.status); return res.status(502).send('Could not complete MyAnimeList login. Check app settings and redirect URL, then try again.'); }
    const session = { tokens: { ...tokens, expires_at: Date.now() + Number(tokens.expires_in || 3600) * 1000 }, connected_at: Date.now() };
    const user = await malFetch('https://api.myanimelist.net/v2/users/@me', tokens.access_token);
    session.user = { id: user.id, name: user.name };
    setSession(res, session);
    res.redirect('/?connected=1');
  } catch (err) { console.error('OAuth callback error:', err.message); res.status(502).send('Could not connect to MyAnimeList. Please verify the API app settings and try again.'); }
});
app.get('/api/me', requireReady, async (req, res) => {
  let session = getSession(req);
  if (!session?.tokens) return res.status(401).json({ connected: false });
  try { session = await refreshIfNeeded(session); const user = await malFetch('https://api.myanimelist.net/v2/users/@me', session.tokens.access_token); session.user = { id: user.id, name: user.name }; setSession(res, session); res.json({ connected: true, user: session.user }); }
  catch (err) { clearSession(res); res.status(401).json({ connected: false, message: 'Please connect MyAnimeList again.' }); }
});
app.get('/api/animelist', requireReady, async (req, res) => {
  let session = getSession(req);
  if (!session?.tokens) return res.status(401).json({ error: 'not_connected', message: 'Connect MyAnimeList first.' });
  try {
    session = await refreshIfNeeded(session);
    const status = typeof req.query.status === 'string' ? req.query.status : '';
    const allowed = new Set(['watching', 'completed', 'on_hold', 'dropped', 'plan_to_watch']);
    if (status && !allowed.has(status)) return res.status(400).json({ error: 'invalid_status' });
    const all = []; let next = new URL('https://api.myanimelist.net/v2/users/@me/animelist');
    next.searchParams.set('limit', '1000');
    next.searchParams.set('fields', 'list_status,num_episodes,media_type,genres,mean,start_season');
    if (status) next.searchParams.set('status', status);
    for (let page = 0; page < 20 && next; page++) {
      const data = await malFetch(next.toString(), session.tokens.access_token);
      all.push(...(data.data || []));
      next = data.paging?.next ? new URL(data.paging.next) : null;
    }
    setSession(res, session);
    const counts = { total: all.length, watching: 0, completed: 0, on_hold: 0, dropped: 0, plan_to_watch: 0 };
    for (const entry of all) { const s = entry.list_status?.status; if (s in counts) counts[s]++; }
    res.json({ user: session.user, fetched_at: new Date().toISOString(), counts, entries: all });
  } catch (err) { console.error('Anime list fetch error:', err.message); res.status(err.status || 502).json({ error: 'mal_request_failed', message: err.message }); }
});
app.post('/auth/logout', (_req, res) => { clearSession(res); res.json({ ok: true }); });
app.get('/auth/logout', (_req, res) => { clearSession(res); res.redirect('/'); });

app.listen(PORT, '0.0.0.0', () => console.log(`MediaHub listening on ${PORT}`));
