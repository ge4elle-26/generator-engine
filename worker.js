/**
 * GE AI - Cloudflare Worker
 * Connects to Firebase Firestore (via REST + JWT) and OpenRouter API.
 *
 * Environment variables required:
 *   OPENROUTER_API_KEY        - OpenRouter API key
 *   FIREBASE_SERVICE_ACCOUNT  - Full JSON string of Firebase service account
 *   FIREBASE_PROJECT_ID       - Firebase project ID
 *   ADMIN_SEED_TOKEN          - Secret token for /admin/seed
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const FIRESTORE_SCOPE = 'https://www.googleapis.com/auth/datastore';
const FIREBASE_JWK_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

// Module-level JWK cache (lives as long as the worker instance)
let _jwkCache = null;
let _jwkCacheAt = 0;

// Phase 9: Scoped memory cache — keyed by scope, 5-minute TTL
const _memoryCache = new Map(); // scope → { items: [], cachedAt: number }
const MEMORY_CACHE_TTL = 5 * 60 * 1000;
const OPENROUTER_API_URL = 'https://openrouter.ai/api/v1/chat/completions';
const OPENROUTER_REFERER = 'https://generator-engine.pages.dev';
const OPENROUTER_TITLE = 'GE Generator Engine';

const MODELS = {
  DEEP:       'anthropic/claude-opus-4-6',      // strategy
  DEFAULT:    'anthropic/claude-sonnet-4-6',    // execute mode chat
  LOGIC:      'openai/gpt-5.4',                  // logic / think mode
  BACKGROUND: 'google/gemini-2.5-flash',        // summarize / classifier
};

const SESSION_MESSAGE_LIMIT = 10;

const VALID_INTENTS = new Set([
  'save_memory', 'recall_memory', 'update_task_state',
  'writing', 'research', 'strategy_logic', 'fallback',
]);

// ---------------------------------------------------------------------------
// JWT / Google Auth
// ---------------------------------------------------------------------------

function base64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function encodeJSON(obj) {
  return base64url(new TextEncoder().encode(JSON.stringify(obj)));
}

async function createGoogleJWT(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);

  const header = encodeJSON({ alg: 'RS256', typ: 'JWT' });
  const payload = encodeJSON({
    iss: serviceAccount.client_email,
    scope: FIRESTORE_SCOPE,
    aud: GOOGLE_TOKEN_URL,
    iat: now,
    exp: now + 3600,
  });

  const signingInput = `${header}.${payload}`;

  const pemBody = serviceAccount.private_key
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/\s/g, '');

  const keyBuffer = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));

  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    keyBuffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    cryptoKey,
    new TextEncoder().encode(signingInput)
  );

  return `${signingInput}.${base64url(signature)}`;
}

async function getGoogleAccessToken(serviceAccount) {
  const jwt = await createGoogleJWT(serviceAccount);
  const res = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Google token error ${res.status}: ${body}`);
  }
  const { access_token } = await res.json();
  return access_token;
}

// ---------------------------------------------------------------------------
// Firestore value serialization / deserialization
// ---------------------------------------------------------------------------

function toFirestoreValue(value) {
  if (value === null || value === undefined) return { nullValue: null };
  if (typeof value === 'boolean') return { booleanValue: value };
  if (typeof value === 'number')
    return Number.isInteger(value)
      ? { integerValue: String(value) }
      : { doubleValue: value };
  if (typeof value === 'string') return { stringValue: value };
  if (Array.isArray(value))
    return { arrayValue: { values: value.map(toFirestoreValue) } };
  if (typeof value === 'object')
    return {
      mapValue: {
        fields: Object.fromEntries(
          Object.entries(value).map(([k, v]) => [k, toFirestoreValue(v)])
        ),
      },
    };
  return { stringValue: String(value) };
}

function fromFirestoreValue(val) {
  if (!val) return null;
  if ('nullValue' in val) return null;
  if ('booleanValue' in val) return val.booleanValue;
  if ('integerValue' in val) return parseInt(val.integerValue, 10);
  if ('doubleValue' in val) return val.doubleValue;
  if ('stringValue' in val) return val.stringValue;
  if ('timestampValue' in val) return val.timestampValue;
  if ('arrayValue' in val)
    return (val.arrayValue.values || []).map(fromFirestoreValue);
  if ('mapValue' in val)
    return fromFirestoreFields(val.mapValue.fields || {});
  return null;
}

function fromFirestoreFields(fields) {
  return Object.fromEntries(
    Object.entries(fields).map(([k, v]) => [k, fromFirestoreValue(v)])
  );
}

function toFirestoreFields(obj) {
  return Object.fromEntries(
    Object.entries(obj).map(([k, v]) => [k, toFirestoreValue(v)])
  );
}

// ---------------------------------------------------------------------------
// Firestore REST client
// ---------------------------------------------------------------------------

class FirestoreClient {
  constructor(projectId, accessToken) {
    this.root = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents`;
    this.accessToken = accessToken;
  }

  get _headers() {
    return {
      Authorization: `Bearer ${this.accessToken}`,
      'Content-Type': 'application/json',
    };
  }

  // GET /collection/docId
  async get(collection, docId) {
    const res = await fetch(`${this.root}/${collection}/${docId}`, {
      headers: this._headers,
    });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`Firestore GET error ${res.status}: ${await res.text()}`);
    const doc = await res.json();
    return fromFirestoreFields(doc.fields || {});
  }

  // PATCH (create or overwrite) /collection/docId
  async set(collection, docId, data) {
    const res = await fetch(`${this.root}/${collection}/${docId}`, {
      method: 'PATCH',
      headers: this._headers,
      body: JSON.stringify({ fields: toFirestoreFields(data) }),
    });
    if (!res.ok) throw new Error(`Firestore SET error ${res.status}: ${await res.text()}`);
    return res.json();
  }

  // POST to collection (auto-ID)
  async add(collectionPath, data) {
    const res = await fetch(`${this.root}/${collectionPath}`, {
      method: 'POST',
      headers: this._headers,
      body: JSON.stringify({ fields: toFirestoreFields(data) }),
    });
    if (!res.ok) throw new Error(`Firestore ADD error ${res.status}: ${await res.text()}`);
    const doc = await res.json();
    return doc.name.split('/').pop();
  }

  // runQuery against a parent path (supports subcollections)
  async query(parentPath, collectionId, { filters = [], orderBy, limit = 20 } = {}) {
    const structuredQuery = {
      from: [{ collectionId }],
      limit,
    };

    if (filters.length === 1) {
      structuredQuery.where = filters[0];
    } else if (filters.length > 1) {
      structuredQuery.where = { compositeFilter: { op: 'AND', filters } };
    }

    if (orderBy) {
      structuredQuery.orderBy = [
        {
          field: { fieldPath: orderBy.field },
          direction: orderBy.direction || 'ASCENDING',
        },
      ];
    }

    const url = parentPath
      ? `${this.root}/${parentPath}:runQuery`
      : `${this.root}:runQuery`;

    const res = await fetch(url, {
      method: 'POST',
      headers: this._headers,
      body: JSON.stringify({ structuredQuery }),
    });
    if (!res.ok) throw new Error(`Firestore QUERY error ${res.status}: ${await res.text()}`);

    const results = await res.json();
    return results
      .filter((r) => r.document)
      .map((r) => ({
        _id: r.document.name.split('/').pop(),
        ...fromFirestoreFields(r.document.fields || {}),
      }));
  }
}

// ---------------------------------------------------------------------------
// Date / session utilities
// ---------------------------------------------------------------------------

function getManilaDateString() {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Manila',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(new Date()); // returns YYYY-MM-DD
}

function buildSessionId(dateStr) {
  return `session_${dateStr}`;
}

// ---------------------------------------------------------------------------
// Think Mode detection
// ---------------------------------------------------------------------------

function detectThinkMode(message) {
  const m = message.trimStart();
  return m.startsWith('/think') || m.toLowerCase().includes('thinking out loud');
}

function stripPrefixes(message) {
  let m = message.trimStart();
  if (m.startsWith('/deep '))  m = m.slice('/deep '.length);
  if (m.startsWith('/think ')) m = m.slice('/think '.length);
  return m;
}

// ---------------------------------------------------------------------------
// Intent classifier — fast non-streaming Gemini Flash pre-call
// Returns: chat | strategy | logic | summarize
// ---------------------------------------------------------------------------

async function classifyIntent(apiKey, message) {
  try {
    const res = await callClaude(apiKey, {
      model: MODELS.BACKGROUND,
      system: `Classify the user message into exactly one intent. Reply with a single word only, no punctuation.
- save_memory: user wants to save, store, or remember a fact, decision, or information
- recall_memory: user wants to retrieve, recall, or look up something previously saved
- update_task_state: user wants to update, complete, create, or change a task or action item
- writing: content creation, copywriting, social media posts, captions, scripts, emails
- research: looking up info, comparison, investigation, asking factual or analytical questions
- strategy_logic: business planning, decisions, goals, calculations, step-by-step reasoning, prioritization
- fallback: general chat, greetings, unclear, or anything not covered above`,
      messages: [{ role: 'user', content: message }],
      maxTokens: 10,
    });
    const raw = res.content[0].text.trim().toLowerCase().split(/\W/)[0];
    return VALID_INTENTS.has(raw) ? raw : 'fallback';
  } catch {
    return 'fallback';
  }
}

// ---------------------------------------------------------------------------
// Scope detector — fast non-streaming Gemini Flash pre-call
// Returns: meatsource | ge-connect | affiliate | global
// ---------------------------------------------------------------------------

async function detectScope(apiKey, message, sessionContext = '') {
  try {
    const res = await callClaude(apiKey, {
      model: MODELS.BACKGROUND,
      system: `Classify the business scope of this message. Reply with a single word only.
- meatsource: frozen meat, pork, chicken, MEATSOURCE, delivery, supplier, margins, cold storage
- ge-connect: co-working, printing, GE Connect Station, lamination, scanning, station
- affiliate: Gabay Essentials, affiliate, health products, wellness, social media, content, TikTok, Instagram
- global: cross-business, personal, AI tools, coding, general, Exis OS, or unclear`,
      messages: [{ role: 'user', content: `Message: ${message}\nContext: ${sessionContext || 'none'}` }],
      maxTokens: 5,
    });
    const scope = res.content[0].text.trim().toLowerCase().split(/\s/)[0];
    return ['meatsource', 'ge-connect', 'affiliate', 'global'].includes(scope) ? scope : 'global';
  } catch {
    return 'global';
  }
}

// ---------------------------------------------------------------------------
// Model router — selects model from intent + mode + explicit preference
// ---------------------------------------------------------------------------

function routeModel(intent, isThinkMode, modelPreference) {
  if (modelPreference === 'opus')          return MODELS.DEEP;
  if (isThinkMode)                         return MODELS.LOGIC;
  if (intent === 'strategy_logic')         return MODELS.DEEP;
  if (intent === 'research')               return MODELS.LOGIC;
  if (intent === 'save_memory'   ||
      intent === 'recall_memory' ||
      intent === 'update_task_state')      return MODELS.BACKGROUND;
  return MODELS.DEFAULT; // writing, fallback, unknown
}

// ---------------------------------------------------------------------------
// Claude API
// ---------------------------------------------------------------------------

// Phase 9: Prompt caching — Anthropic models support cache_control on system prompt
function buildOpenRouterMessages(system, messages, model = '') {
  if (!system) return messages;
  const isAnthropic = model.startsWith('anthropic/');
  const systemContent = isAnthropic
    ? [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }]
    : system;
  return [{ role: 'system', content: systemContent }, ...messages];
}

// Non-streaming call — used by extractMemoryItems and fallback
async function callClaude(apiKey, { model, system, messages, maxTokens = 2048 }) {
  const res = await fetch(OPENROUTER_API_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'HTTP-Referer': OPENROUTER_REFERER,
      'X-Title': OPENROUTER_TITLE,
    },
    body: JSON.stringify({ model, max_tokens: maxTokens, messages: buildOpenRouterMessages(system, messages, model) }),
  });
  if (!res.ok) {
    const errBody = await res.text();
    throw new Error(`OpenRouter API error ${res.status}: ${errBody.substring(0, 300)}`);
  }
  const data = await res.json();
  return {
    content: [{ text: data.choices?.[0]?.message?.content ?? '' }],
    usage: data.usage,
  };
}

// Streaming call — returns raw fetch Response with SSE body
async function callClaudeStream(apiKey, { model, system, messages, maxTokens = 2048 }) {
  const res = await fetch(OPENROUTER_API_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'HTTP-Referer': OPENROUTER_REFERER,
      'X-Title': OPENROUTER_TITLE,
    },
    body: JSON.stringify({ model, max_tokens: maxTokens, stream: true, messages: buildOpenRouterMessages(system, messages, model) }),
  });
  return res;
}

// Phase 10: Scoped memory — pinned items always first, then recent unpinned
async function loadScopedMemory(db, scope) {
  const now = Date.now();
  const cached = _memoryCache.get(scope);
  if (cached && now - cached.cachedAt < MEMORY_CACHE_TTL) {
    console.log(`[ge-ai] memory cache HIT scope=${scope} (${cached.items.length} items)`);
    return cached.items;
  }

  const scopeFilter = {
    fieldFilter: { field: { fieldPath: 'scope' }, op: 'EQUAL', value: { stringValue: scope } },
  };

  const [pinnedItems, unpinnedItems] = await Promise.all([
    db.query('', 'memory', {
      filters: [
        scopeFilter,
        { fieldFilter: { field: { fieldPath: 'pinned' }, op: 'EQUAL', value: { booleanValue: true } } },
      ],
      orderBy: { field: 'createdAt', direction: 'DESCENDING' },
      limit: 20,
    }),
    db.query('', 'memory', {
      filters: [
        scopeFilter,
        { fieldFilter: { field: { fieldPath: 'pinned' }, op: 'EQUAL', value: { booleanValue: false } } },
      ],
      orderBy: { field: 'createdAt', direction: 'DESCENDING' },
      limit: 10,
    }),
  ]);

  const items = [...pinnedItems, ...unpinnedItems];
  _memoryCache.set(scope, { items, cachedAt: now });
  console.log(`[ge-ai] memory cache MISS scope=${scope} — ${pinnedItems.length} pinned + ${unpinnedItems.length} unpinned = ${items.length} items`);
  return items;
}

function invalidateScopeCache(scope) {
  _memoryCache.delete(scope);
  console.log(`[ge-ai] memory cache invalidated scope=${scope}`);
}

async function withRetry(fn, retries = 1, delayMs = 500) {
  try { return await fn(); } catch (err) {
    if (retries <= 0) throw err;
    await new Promise(r => setTimeout(r, delayMs));
    return withRetry(fn, retries - 1, delayMs);
  }
}

// Smart memory: always load rules+prefs (max 5 each), plus keyword matches (max 5)
const STOP_WORDS = new Set(['what','this','that','with','from','have','will','your','about','which','when','where','does','into','more','been','also','than','then','only','some','them','they','were','would','could','should','there','their','these','those','just','like','much','very','over','such','even','most','both','each','here','make','well','after','before','while','being']);

function extractKeywords(text) {
  return [...new Set(
    text.toLowerCase()
      .split(/\W+/)
      .filter(w => w.length >= 4 && !STOP_WORDS.has(w))
  )];
}

async function loadRelevantMemory(db, userMessage) {
  const allActive = await db.query('', 'memory_core', {
    filters: [{ fieldFilter: { field: { fieldPath: 'status' }, op: 'EQUAL', value: { stringValue: 'active' } } }],
    limit: 200,
  });

  const keywords = extractKeywords(userMessage);

  const rules = allActive.filter(i => i.type === 'rule').slice(0, 5);
  const prefs = allActive.filter(i => i.type === 'preference').slice(0, 5);

  const alreadyIncluded = new Set([...rules, ...prefs].map(i => i._id));

  let keywordMatches = [];
  if (keywords.length > 0) {
    keywordMatches = allActive
      .filter(i => !alreadyIncluded.has(i._id))
      .filter(i => {
        const haystack = `${i.title || ''} ${i.content || ''}`.toLowerCase();
        return keywords.some(kw => haystack.includes(kw));
      })
      .slice(0, 5);
  }

  const selected = [...rules, ...prefs, ...keywordMatches];
  console.log(`[ge-ai] memory: ${selected.length} items loaded (${rules.length} rules, ${prefs.length} prefs, ${keywordMatches.length} keyword) | keywords: [${keywords.join(', ')}]`);
  return selected;
}

// ---------------------------------------------------------------------------
// Firebase ID token verification
// ---------------------------------------------------------------------------

async function getFirebaseJwks() {
  const now = Date.now();
  if (_jwkCache && now - _jwkCacheAt < 3_600_000) return _jwkCache;
  const res = await fetch(FIREBASE_JWK_URL);
  if (!res.ok) throw new Error('Failed to fetch Firebase public keys');
  _jwkCache = await res.json();
  _jwkCacheAt = now;
  return _jwkCache;
}

function b64urlToStr(s) {
  return atob(s.replace(/-/g, '+').replace(/_/g, '/'));
}

async function verifyFirebaseToken(token, projectId) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Malformed token');

  let header, payload;
  try {
    header  = JSON.parse(b64urlToStr(parts[0]));
    payload = JSON.parse(b64urlToStr(parts[1]));
  } catch {
    throw new Error('Invalid token encoding');
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now)                                throw new Error('Token expired');
  if (payload.aud !== projectId)                        throw new Error('Invalid audience');
  if (payload.iss !== `https://securetoken.google.com/${projectId}`) throw new Error('Invalid issuer');
  if (!payload.sub)                                     throw new Error('Missing subject');

  const jwks = await getFirebaseJwks();
  const jwk  = (jwks.keys || []).find(k => k.kid === header.kid);
  if (!jwk) throw new Error('Public key not found');

  const publicKey = await crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['verify']
  );

  const sigBytes = Uint8Array.from(b64urlToStr(parts[2]), c => c.charCodeAt(0));
  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5', publicKey, sigBytes,
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  );
  if (!valid) throw new Error('Signature invalid');

  return { uid: payload.sub, email: payload.email || null };
}

async function requireAuth(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  if (!authHeader.startsWith('Bearer ')) {
    return { authError: errorResponse('Unauthorized', 401) };
  }
  try {
    const user = await verifyFirebaseToken(authHeader.slice(7), env.FIREBASE_PROJECT_ID);
    return { user };
  } catch (e) {
    return { authError: errorResponse(`Unauthorized: ${e.message}`, 401) };
  }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

function corsPreflightResponse() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, x-admin-token, Authorization',
      'Access-Control-Max-Age': '86400',
    },
  });
}

// SSE response carrying a controlled error — frontend handles it identically to a normal response
function sseErrorResponse(message, sessionId, intent, model, scope, statusCode = 'error') {
  const enc = new TextEncoder();
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  (async () => {
    try {
      await writer.write(enc.encode(`data: ${JSON.stringify({ type: 'text', content: message })}\n\n`));
      await writer.write(enc.encode(`data: ${JSON.stringify({
        type:          'done',
        message,
        intent:        intent  || 'fallback',
        model:         model   || 'unknown',
        scope:         scope   || 'global',
        memory_loaded: 0,
        session_id:    sessionId || '',
        status:        statusCode,
        runtime_degraded: true,
      })}\n\n`));
    } finally {
      await writer.close();
    }
  })();
  return new Response(readable, {
    status: 200,
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Transfer-Encoding': 'chunked',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}

// ---------------------------------------------------------------------------
// Shared Firestore init helper
// ---------------------------------------------------------------------------

async function initFirestore(env) {
  const serviceAccount = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const accessToken = await getGoogleAccessToken(serviceAccount);
  return new FirestoreClient(env.FIREBASE_PROJECT_ID, accessToken);
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

// POST /summarize-session — summarize a session and persist to session_summaries/{session_id}
async function handleSummarizeSession(request, env) {
  const { authError } = await requireAuth(request, env);
  if (authError) return authError;

  let body;
  try { body = await request.json(); } catch { return errorResponse('Invalid JSON body'); }

  const { session_id, scope } = body;
  if (!session_id) return errorResponse('session_id is required');

  const db = await initFirestore(env);

  const msgs = await db.query(`sessions/${session_id}`, 'messages', {
    orderBy: { field: 'createdAt', direction: 'ASCENDING' },
    limit: 50,
  }).catch(() => []);

  if (msgs.length === 0) return jsonResponse({ skipped: true, reason: 'no messages' });

  const transcript = msgs
    .map(m => `${m.role === 'user' ? 'User' : 'GE'}: ${(m.content || '').substring(0, 400)}`)
    .join('\n');

  let summary = '';
  try {
    const res = await callClaude(env.OPENROUTER_API_KEY, {
      model: MODELS.BACKGROUND,
      system: 'Summarize this conversation in 3-5 sentences. Focus on key decisions made, facts shared, and context that matters for future sessions. Be factual and concise.',
      messages: [{ role: 'user', content: transcript }],
      maxTokens: 300,
    });
    summary = res.content[0]?.text?.trim() || '';
  } catch (e) {
    console.error('[ge-ai] summarize failed:', e.message);
    return errorResponse('Summarization failed', 500);
  }

  const now = new Date().toISOString();
  await db.set('session_summaries', session_id, {
    summary,
    session_id,
    scope: scope || 'global',
    created_at: now,
  });

  return jsonResponse({ session_id, scope: scope || 'global', summary });
}

// GET /config — returns public Firebase client config (key stored as worker secret)
async function handleConfig(env) {
  const apiKey = env.FIREBASE_API_KEY;
  if (!apiKey) return errorResponse('Config not available', 503);
  return jsonResponse({ apiKey });
}

// GET /active-session — returns the last active session for the authenticated user
async function handleActiveSession(request, env) {
  const { user, authError } = await requireAuth(request, env);
  if (authError) return authError;

  const db = await initFirestore(env);
  const data = await db.get('users', user.uid).catch(() => null);

  if (!data?.session_id) return jsonResponse({ active: false });
  return jsonResponse({ active: true, session_id: data.session_id, scope: data.scope || 'global' });
}

// GET /health
async function handleHealth() {
  const date = getManilaDateString();
  return jsonResponse({
    status: 'ok',
    worker: 'ge-ai',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    session: buildSessionId(date),
    manila_date: date,
  });
}

// POST /chat
async function handleChat(request, env, ctx) {
  const { user, authError } = await requireAuth(request, env);
  if (authError) return authError;

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body');
  }

  const { message, session_id, max_tokens, image, model_preference, conversation_id: incomingConvId } = body;
  if (!message || typeof message !== 'string')
    return errorResponse('message (string) is required');

  if (image && image.length * 0.75 > 4 * 1024 * 1024)
    return errorResponse('Image too large, max 4MB', 400);

  const isThinkMode = detectThinkMode(message);
  const cleanMessage = stripPrefixes(message);
  const conversationId = incomingConvId || crypto.randomUUID();

  const db = await initFirestore(env);
  const date = getManilaDateString();
  const sessionId = session_id || crypto.randomUUID();

  // Load system config + smart memory + classify intent + detect scope — all in parallel
  // Phase 4.6: Firestore read failures are isolated — degrade gracefully, never abort
  const recentContext = '';
  let firestoreDegraded = false;
  const fsReadFail = label => e => {
    console.error(`[ge-ai] Firestore read failed (${label}):`, e.message);
    firestoreDegraded = true;
    return null;
  };

  const [identity, sysRules, sysPrefs, relevantMemory, recentRaw, intent, scope] = await Promise.all([
    db.get('system_config', 'identity').catch(fsReadFail('identity')),
    db.get('system_config', 'rules').catch(fsReadFail('rules')),
    db.get('system_config', 'preferences').catch(fsReadFail('preferences')),
    withRetry(() => loadRelevantMemory(db, cleanMessage)).catch(e => { console.error('[ge-ai] memory read failed after retry:', e.message); firestoreDegraded = true; return []; }),
    db.query(`sessions/${sessionId}`, 'messages', {
      orderBy: { field: 'createdAt', direction: 'DESCENDING' },
      limit: SESSION_MESSAGE_LIMIT,
    }).catch(e => { console.error('[ge-ai] session read failed:', e.message); firestoreDegraded = true; return []; }),
    classifyIntent(env.OPENROUTER_API_KEY, cleanMessage),
    detectScope(env.OPENROUTER_API_KEY, cleanMessage, recentContext),
  ]);

  let model = routeModel(intent, isThinkMode, model_preference);
  if (image && model === MODELS.BACKGROUND) model = MODELS.DEFAULT;

  // Phase 4: Normalize to safe defaults — never let a bad value break the pipeline
  const validatedIntent = VALID_INTENTS.has(intent) ? intent : 'fallback';
  const validatedScope  = scope  || 'global';
  const validatedModel  = model  || MODELS.DEFAULT;
  if (validatedIntent !== intent || !scope || !model) {
    console.warn(`[ge-ai] validation normalised: intent=${intent}→${validatedIntent} scope=${scope||'(missing)'} model=${model||'(missing)'}`);
  }

  // Phase 10: Load scoped memory (pinned first) and previous session summary in parallel
  const [scopedMemory, prevSummaryItems] = await Promise.all([
    withRetry(() => loadScopedMemory(db, validatedScope)).catch(e => {
      console.error('[ge-ai] scoped memory load failed after retry:', e.message);
      return [];
    }),
    db.query('', 'session_summaries', {
      filters: [{ fieldFilter: { field: { fieldPath: 'scope' }, op: 'EQUAL', value: { stringValue: validatedScope } } }],
      orderBy: { field: 'created_at', direction: 'DESCENDING' },
      limit: 1,
    }).catch(() => []),
  ]);
  const prevSummary = prevSummaryItems[0] || null;

  // Build system prompt
  const systemSections = [];

  // GE self-awareness — always first block
  systemSections.push(`# GE — Generator Engine V2.2
System: Generator Engine V2.2 | Owner: Gerald Reyes | Date (Manila): ${date} | Scope: ${validatedScope}
Phases complete: 1, 2, 3, 3.5, 4, 4.5, 4.6, 5, 6, 6.5, 8, 9, 10
Infrastructure: Cloudflare Worker + Pages · OpenRouter multi-model · Firebase Auth + Firestore
Models: claude-opus-4-6 (strategy) · claude-sonnet-4-6 (execute) · gpt-5.4 (logic/think) · gemini-2.5-flash (background)`);

  if (identity?.content) systemSections.push(`# Identity\n${identity.content}`);
  if (sysRules?.content) systemSections.push(`# Rules\n${sysRules.content}`);
  if (sysPrefs?.content) systemSections.push(`# Preferences\n${sysPrefs.content}`);

  if (isThinkMode) {
    systemSections.push(`# Think Mode — Socratic Reasoning Partner
You are in Think Mode. Your job is NOT to give answers — it is to help Gerald think.
1. Ask 1–3 focused clarifying questions that expose hidden assumptions or trade-offs
2. Do NOT offer a recommendation or solution yet
3. Mirror back what you heard to confirm understanding
4. If the situation is clear, surface the single most important question he hasn't asked himself
5. Short responses only — this is a dialogue, not a monologue
Tone: curious, direct, no filler.`);
  } else {
    systemSections.push(`# Execute Mode — Thinking Partner Behavior
You are Gerald's thinking partner, not a fact lookup. When answering:
1. Lead with the direct answer first — always, no preamble
2. Add ONE useful line of context or connection to his business
3. When relevant, offer a specific proactive next step (e.g. "Want me to calculate today's pricing?")
4. If a question touches multiple businesses or rules, connect the dots
5. NEVER end with generic fluff like "Is there anything else?" — suggest specific next actions or say nothing
6. Use what you know about Gerald actively — don't wait to be asked

Tone: direct, no filler, no fake enthusiasm. Filipino terms acceptable where natural.`);
  }

  if (relevantMemory.length > 0) {
    const groups = {};
    for (const item of relevantMemory) {
      const t = item.type || 'fact';
      if (!groups[t]) groups[t] = [];
      groups[t].push(`- [${item.title}] ${item.content}`);
    }
    const labelMap = { fact: 'KNOWN FACTS', decision: 'DECISIONS', rule: 'BUSINESS RULES', preference: 'USER PREFERENCES', business_info: 'BUSINESS INFORMATION' };
    systemSections.push(`# Memory (${relevantMemory.length} items)\n` +
      Object.entries(groups).map(([t, lines]) => `## ${labelMap[t] || t.toUpperCase()}\n${lines.join('\n')}`).join('\n\n'));
  }

  // Phase 9: Inject scoped memory (user-approved, cached)
  if (scopedMemory.length > 0) {
    const lines = scopedMemory.map(m => `- ${m.content}`).join('\n');
    systemSections.push(`# Scoped Memory [${validatedScope}] (${scopedMemory.length} items, cached)\n${lines}`);
  }

  if (prevSummary?.summary) {
    systemSections.push(`# Previous Session Context [${validatedScope}]\n${prevSummary.summary}`);
  }

  systemSections.push(`# Session\nID: ${sessionId} | Conv: ${conversationId} | Date (Manila): ${date} | Model: ${validatedModel} | Intent: ${validatedIntent} | Scope: ${validatedScope}${isThinkMode ? ' | Mode: think' : ''}`);
  const systemPrompt = systemSections.join('\n\n');

  const recentMessages = recentRaw
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
    .map(({ role, content }) => ({ role, content }));

  // Build user content (text or text+image)
  let userContent;
  if (image) {
    const mediaType = image.startsWith('data:image/png') ? 'image/png'
      : image.startsWith('data:image/gif') ? 'image/gif'
      : image.startsWith('data:image/webp') ? 'image/webp'
      : 'image/jpeg';
    userContent = [
      { type: 'image', source: { type: 'base64', media_type: mediaType, data: image.replace(/^data:[^;]+;base64,/, '') } },
      { type: 'text', text: cleanMessage },
    ];
  } else {
    userContent = cleanMessage;
  }

  const messagesForClaude = [...recentMessages, { role: 'user', content: userContent }];

  // Phase 4.6: OpenRouter fetch with retry + structured error handling
  const orOpts = { model: validatedModel, system: systemPrompt, messages: messagesForClaude, maxTokens: max_tokens || 2048 };
  let upstream;
  try {
    upstream = await callClaudeStream(env.OPENROUTER_API_KEY, orOpts);
    if (upstream.status === 429) {
      console.warn('[ge-ai] OpenRouter 429 — retrying after 1s');
      await new Promise(r => setTimeout(r, 1000));
      upstream = await callClaudeStream(env.OPENROUTER_API_KEY, orOpts);
    }
  } catch (netErr) {
    console.error('[ge-ai] OpenRouter network error:', netErr.message);
    return sseErrorResponse('Connection issue — please try again.', sessionId, validatedIntent, validatedModel, validatedScope, 'network_error');
  }

  if (upstream.status === 429) {
    console.error('[ge-ai] OpenRouter still 429 after retry');
    return sseErrorResponse('GE is busy — please try again in a moment.', sessionId, validatedIntent, validatedModel, validatedScope, 'rate_limited');
  }
  if (upstream.status === 401 || upstream.status === 403) {
    console.error(`[ge-ai] OpenRouter auth error ${upstream.status}`);
    return sseErrorResponse('Provider authentication issue — please contact support.', sessionId, validatedIntent, validatedModel, validatedScope, 'auth_error');
  }
  if (!upstream.ok) {
    const errBody = await upstream.text().catch(() => '');
    console.error(`[ge-ai] OpenRouter error ${upstream.status}: ${errBody.substring(0, 200)}`);
    return sseErrorResponse('GE encountered an error — please try again.', sessionId, validatedIntent, validatedModel, validatedScope, 'provider_error');
  }

  // Pipe SSE chunks to frontend via TransformStream
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const enc = new TextEncoder();
  let fullText = '';

  const processStream = async () => {
    const reader = upstream.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    let responseStatus = 'ok'; // hoisted so log can read it after finally

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop() ?? '';
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const raw = line.slice(6).trim();
          if (raw === '[DONE]') continue;
          try {
            const chunk = JSON.parse(raw);
            const text = chunk.choices?.[0]?.delta?.content;
            if (text) {
              fullText += text;
              await writer.write(enc.encode(`data: ${JSON.stringify({ type: 'text', content: text })}\n\n`));
            }
          } catch { /* skip malformed chunk */ }
        }
      }
    } finally {
      // Phase 4: Validate response — inject fallback if empty
      if (!fullText || fullText.trim().length === 0) {
        const fallback = 'Something went wrong — please try again.';
        await writer.write(enc.encode(`data: ${JSON.stringify({ type: 'text', content: fallback })}\n\n`));
        fullText = fallback;
        responseStatus = 'fallback';
        console.error('[ge-ai] empty response — fallback injected');
      }

      // Phase 4.5: Schema-enforced done event — all fields always present
      await writer.write(enc.encode(`data: ${JSON.stringify({
        type:             'done',
        message:          fullText,
        intent:           validatedIntent,
        model:            validatedModel,
        scope:            validatedScope,
        memory_loaded:    relevantMemory.length,
        session_id:       sessionId,
        status:           responseStatus,
        runtime_degraded: firestoreDegraded,
        // backward-compat
        conversation_id:  conversationId,
        think_mode:       isThinkMode,
        memory_items:     relevantMemory.length,
      })}\n\n`));
      await writer.close();
    }

    // Phase 4.6: Firestore write — log on failure, never block the response
    const now = new Date().toISOString();
    const imageSmall = image && image.length < 100 * 1024;
    try {
      await Promise.all([
        db.add(`sessions/${sessionId}/messages`, {
          role: 'user',
          content: image ? `[📷 image attached] ${cleanMessage}` : cleanMessage,
          createdAt: now, sessionId, conversationId,
          model: validatedModel, intent: validatedIntent, scope: validatedScope,
          think_mode: isThinkMode, has_image: !!image,
          user_id: user.uid,
          ...(imageSmall ? { image_data: image } : {}),
        }),
        db.add(`sessions/${sessionId}/messages`, {
          role: 'assistant', content: fullText,
          createdAt: new Date().toISOString(), sessionId, conversationId,
          model: validatedModel, intent: validatedIntent, scope: validatedScope,
          think_mode: isThinkMode, user_id: user.uid,
        }),
      ]);
    } catch (writeErr) {
      console.error('[ge-ai] Firestore write failed (non-blocking):', writeErr.message);
    }

    // Phase 10: Cross-device continuity — save active session under users/{uid}
    try {
      await db.set('users', user.uid, {
        session_id: sessionId,
        scope: validatedScope,
        updated_at: new Date().toISOString(),
      });
    } catch (e) {
      console.error('[ge-ai] user session save failed:', e.message);
    }

    // Phase 6: Runtime log — fire and forget, never blocks response
    try {
      await db.add('runtime_logs', {
        request_id:       crypto.randomUUID(),
        session_id:       sessionId,
        user_message:     cleanMessage.substring(0, 200),
        detected_intent:  validatedIntent,
        detected_mode:    isThinkMode ? 'think' : 'execute',
        selected_model:   validatedModel,
        scope:            validatedScope,
        memory_loaded:    relevantMemory.length,
        validation_result: responseStatus,
        fallback_used:    responseStatus !== 'ok',
        runtime_degraded: firestoreDegraded,
        created_at:       new Date().toISOString(),
      });
    } catch (logErr) {
      console.error('[ge-ai] Runtime log write failed:', logErr.message);
    }
  };

  ctx.waitUntil(processStream());

  return new Response(readable, {
    status: 200,
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Transfer-Encoding': 'chunked',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}

// GET /recall — returns all items from `memory` collection (ordered by createdAt desc)
async function handleRecallMemory(request, env) {
  const { authError } = await requireAuth(request, env);
  if (authError) return authError;

  const url = new URL(request.url);
  const limitParam = parseInt(url.searchParams.get('limit')) || 50;
  const limit = Math.min(limitParam, 200);

  const db = await initFirestore(env);
  const items = await db.query('', 'memory', {
    orderBy: { field: 'createdAt', direction: 'DESCENDING' },
    limit,
  });

  return jsonResponse({ count: items.length, items });
}

// POST /recall
async function handleRecall(request, env) {
  const { authError } = await requireAuth(request, env);
  if (authError) return authError;

  let body = {};
  try {
    body = await request.json();
  } catch { /* optional body */ }

  const db = await initFirestore(env);
  const date = getManilaDateString();
  const sessionId = body.session_id || buildSessionId(date);
  const limit = Math.min(parseInt(body.limit) || 50, 200);
  const last = body.last === true;

  const sessionParent = `sessions/${sessionId}`;
  const raw = await db.query(sessionParent, 'messages', {
    orderBy: { field: 'createdAt', direction: last ? 'DESCENDING' : 'ASCENDING' },
    limit,
  });
  const messages = last ? [...raw].reverse() : raw;

  return jsonResponse({ session_id: sessionId, count: messages.length, messages });
}

// Split text into chunks at paragraph or sentence boundaries
function chunkText(text, maxSize = 2500) {
  if (text.length <= maxSize) return [text];

  const chunks = [];
  const paragraphs = text.split(/\n{2,}/);
  let current = '';

  for (const para of paragraphs) {
    const candidate = current ? `${current}\n\n${para}` : para;
    if (candidate.length > maxSize && current.length > 0) {
      chunks.push(current.trim());
      current = para;
    } else {
      current = candidate;
    }
  }
  if (current.trim()) chunks.push(current.trim());

  // Second pass: split any still-oversized chunks by sentences
  const result = [];
  for (const chunk of chunks) {
    if (chunk.length <= maxSize) { result.push(chunk); continue; }
    const sentences = chunk.split(/(?<=[.!?])\s+/);
    let cur = '';
    for (const s of sentences) {
      const candidate = cur ? `${cur} ${s}` : s;
      if (candidate.length > maxSize && cur.length > 0) {
        result.push(cur.trim());
        cur = s;
      } else { cur = candidate; }
    }
    if (cur.trim()) result.push(cur.trim());
  }

  return result.filter(c => c.length > 0);
}

// Extract individual memory items from text using Claude
async function extractMemoryItems(apiKey, content, source) {
  const minItems = content.length > 500 ? 10 : 3;
  const extractPrompt = `You are a precise memory extraction assistant. Extract EVERY distinct fact, decision, rule, and preference from the text below as SEPARATE individual items.

RULES:
- Each item must be ONE distinct piece of information — do NOT merge multiple facts into one item
- For content of ${content.length} characters, extract a MINIMUM of ${minItems} items
- Over-extract rather than under-extract

EXAMPLES OF CORRECT SPLITTING:
BAD: "Gerald lives in Cubao and is an entrepreneur" → 1 item
GOOD: "Gerald lives in Cubao, QC" + "Gerald is an entrepreneur" → 2 items

ITEM TYPES:
- fact: specific concrete information about a person, place, or thing
- decision: a choice made or commitment taken
- rule: a guideline, policy, or constraint to follow
- preference: a personal or business preference about style/approach
- business_info: information about a business, product, or service

Return ONLY a valid JSON array with NO markdown formatting, NO code blocks, NO explanation:
[{"type":"fact","title":"short title max 60 chars","content":"full text of this single item","business":"business name or null","confidence":0.9}]

TEXT TO EXTRACT FROM:
${content}`;

  try {
    const claudeRes = await callClaude(apiKey, {
      model: MODELS.DEFAULT,
      system: 'You are a precise memory extraction assistant. Return only valid JSON arrays with no markdown.',
      messages: [{ role: 'user', content: extractPrompt }],
      maxTokens: 4096,
    });
    const raw = claudeRes.content?.[0]?.text ?? '[]';
    const cleaned = raw.replace(/^```(?:json)?\n?/m, '').replace(/\n?```$/m, '').trim();
    const items = JSON.parse(cleaned);
    return Array.isArray(items) ? items : [];
  } catch (e) {
    console.error('[ge-ai] extractMemoryItems failed:', e.message);
    return [{ type: 'fact', title: `Import from ${source}`, content: content.substring(0, 500), business: null, confidence: 0.5 }];
  }
}

// POST /import
async function handleImport(request, env) {
  const { authError } = await requireAuth(request, env);
  if (authError) return authError;

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body');
  }

  const { collection, documents } = body;
  if (!collection || typeof collection !== 'string')
    return errorResponse('collection (string) is required');
  if (!Array.isArray(documents) || documents.length === 0)
    return errorResponse('documents (non-empty array) is required');

  const db = await initFirestore(env);
  const batchId = crypto.randomUUID();
  const importedAt = new Date().toISOString();
  const allItems = [];
  let totalChunks = 0;

  for (const docItem of documents) {
    const docSource = docItem.source || 'unknown';
    const content = docItem.content || '';

    if (content.length > 0) {
      const chunks = chunkText(content, 2500);
      console.log(`[ge-ai] import batch=${batchId} source=${docSource} chunks=${chunks.length} total_chars=${content.length}`);

      for (let i = 0; i < chunks.length; i++) {
        try {
          const items = await extractMemoryItems(env.OPENROUTER_API_KEY, chunks[i], docSource);
          console.log(`[ge-ai] chunk ${i + 1}/${chunks.length}: extracted ${items.length} items`);
          for (const item of items) {
            await db.add('memory_core', {
              ...item,
              source: docSource,
              status: 'active',
              imported_at: importedAt,
              batch_id: batchId,
              session_id: docItem.session_id || null,
            });
            allItems.push(item);
          }
          totalChunks++;
        } catch (e) {
          console.error(`[ge-ai] chunk ${i + 1}/${chunks.length} failed:`, e.message);
        }
      }
    } else {
      const { id, ...fields } = docItem;
      const payload = { ...fields, imported_at: importedAt, batch_id: batchId, status: 'active' };
      id ? await db.set(collection, String(id), payload) : await db.add(collection, payload);
      allItems.push({ type: 'fact', title: 'Raw import', content: '', business: null, confidence: 1 });
    }
  }

  return jsonResponse({ imported: allItems.length, chunks_processed: totalChunks, batch_id: batchId, items: allItems });
}

// POST /save  — Phase 5: writes to memory_updates as a pending proposal
async function handleSave(request, env) {
  const { user, authError } = await requireAuth(request, env);
  if (authError) return authError;

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body');
  }

  const { content, scope, tags, pinned, session_id } = body;
  if (!content || typeof content !== 'string')
    return errorResponse('content (string) is required');

  const db = await initFirestore(env);
  const now = new Date().toISOString();

  const newId = await db.add('memory_updates', {
    content,
    scope:       scope || 'global',
    tags:        Array.isArray(tags) ? tags : [],
    pinned:      pinned === true,
    session_id:  session_id || null,
    status:      'pending',
    confidence:  0.8,
    proposed_at: now,
    user_id:     user.uid,
  });

  return jsonResponse({ id: newId, collection: 'memory_updates', action: 'proposed' });
}

// GET /admin/memory
async function handleAdminMemory(request, env) {
  const token = request.headers.get('x-admin-token');
  if (!token || token !== env.ADMIN_SEED_TOKEN)
    return errorResponse('Unauthorized', 401);

  const db = await initFirestore(env);
  const statusParam = new URL(request.url).searchParams.get('status') || 'active';

  const docs = await db.query('', 'memory_core', {
    filters: [{
      fieldFilter: {
        field: { fieldPath: 'status' },
        op: 'EQUAL',
        value: { stringValue: statusParam },
      },
    }],
    limit: 200,
  });

  return jsonResponse({ count: docs.length, status: statusParam, items: docs });
}

// POST /admin/seed
async function handleAdminSeed(request, env) {
  // Validate token from header or body
  const headerToken = request.headers.get('x-admin-token');
  let bodyToken;
  try {
    const body = await request.json();
    bodyToken = body?.token;
  } catch { /* no body */ }

  const token = headerToken || bodyToken;
  if (!token || token !== env.ADMIN_SEED_TOKEN)
    return errorResponse('Unauthorized: invalid or missing ADMIN_SEED_TOKEN', 401);

  const db = await initFirestore(env);
  const now = new Date().toISOString();

  const seeds = [
    // 1. System identity
    {
      collection: 'system_config',
      id: 'identity',
      data: {
        label: 'System Identity',
        content:
          'You are GE AI, an intelligent and professional AI assistant designed for business productivity. ' +
          'You are knowledgeable, concise, and consistently helpful. You maintain context within each session ' +
          'and provide accurate, well-structured responses. When analysis is needed, you think step-by-step ' +
          'before responding.',
        version: '1.0',
        createdAt: now,
        updatedAt: now,
      },
    },

    // 2. Operational rules
    {
      collection: 'system_config',
      id: 'rules',
      data: {
        label: 'Operational Rules',
        content:
          '1. Be accurate — if uncertain, state it clearly.\n' +
          '2. Be concise — omit filler; every sentence should add value.\n' +
          '3. Respect privacy — never expose PII or sensitive business data in responses.\n' +
          '4. Maintain session context — use prior messages within the session before asking for clarification.\n' +
          '5. Format clearly — use markdown, bullet points, and code blocks where helpful.\n' +
          '6. Confirm actions — acknowledge when a task is complete.\n' +
          '7. Escalate ambiguity — ask a clarifying question rather than guess on high-stakes decisions.\n' +
          '8. /deep prefix — engage deeper reasoning and produce more thorough analysis.',
        version: '1.0',
        createdAt: now,
        updatedAt: now,
      },
    },

    // 3. User preferences
    {
      collection: 'system_config',
      id: 'preferences',
      data: {
        label: 'User Preferences',
        content:
          '- Tone: professional yet approachable\n' +
          '- Language: English; Filipino terms acceptable where natural\n' +
          '- Timezone: Asia/Manila (UTC+8)\n' +
          '- Date format: YYYY-MM-DD\n' +
          '- Default response length: medium (3–6 paragraphs or equivalent bullets)\n' +
          '- Code: always wrapped in fenced code blocks with language identifier\n' +
          '- Default model: claude-sonnet-4-6\n' +
          '- Deep analysis model: claude-opus-4-6 (triggered by /deep prefix)\n' +
          '- Background/summarization model: claude-haiku-4-5-20251001',
        version: '1.0',
        createdAt: now,
        updatedAt: now,
      },
    },

    // 4. Business overview
    {
      collection: 'system_config',
      id: 'business_overview',
      data: {
        label: 'Business Overview',
        type: 'business',
        content:
          'GE AI is the central intelligence layer for business operations. ' +
          'It supports decision-making, document analysis, customer interaction management, ' +
          'and operational automation. The platform is designed to scale from individual ' +
          'productivity tools to enterprise-grade automation pipelines, with full auditability ' +
          'of AI actions via Firestore session logs.',
        version: '1.0',
        createdAt: now,
        updatedAt: now,
      },
    },

    // 5. Business processes
    {
      collection: 'system_config',
      id: 'business_processes',
      data: {
        label: 'Business Processes',
        type: 'business',
        content:
          'Core processes supported by GE AI:\n' +
          '1. Customer Inquiry Handling — AI-drafted responses reviewed by staff before sending.\n' +
          '2. Document Analysis — Extract key data points from contracts, reports, and invoices.\n' +
          '3. Automated Reporting — Generate daily/weekly summaries from structured data.\n' +
          '4. Knowledge Management — Centralized retrieval of SOPs, policies, and guidelines.\n' +
          '5. Decision Support — Data-driven recommendations with explicit confidence levels.\n' +
          '6. Session Logging — All interactions stored in Firestore for compliance and training.',
        version: '1.0',
        createdAt: now,
        updatedAt: now,
      },
    },

    // 6. Business guidelines
    {
      collection: 'system_config',
      id: 'business_guidelines',
      data: {
        label: 'Business Guidelines',
        type: 'business',
        content:
          'Guidelines for responsible AI use within business operations:\n' +
          '- All externally facing AI-generated content must be reviewed by a human before delivery.\n' +
          '- Customer data must be handled in compliance with applicable privacy regulations (Data Privacy Act).\n' +
          '- High-stakes decisions (financial, legal, HR) require human sign-off regardless of AI recommendation.\n' +
          '- Session logs in Firestore should be retained for a minimum of 90 days for auditability.\n' +
          '- AI outputs are advisory — employees retain final responsibility for actions taken.\n' +
          '- Report anomalous or unexpected AI behavior to the system administrator immediately.',
        version: '1.0',
        createdAt: now,
        updatedAt: now,
      },
    },
  ];

  const results = [];
  for (const seed of seeds) {
    await db.set(seed.collection, seed.id, seed.data);
    results.push({ collection: seed.collection, id: seed.id, status: 'seeded' });
  }

  return jsonResponse({ seeded: results.length, results, timestamp: now });
}

// POST /admin/seed-memory
async function handleAdminSeedMemory(request, env) {
  const db = await initFirestore(env);
  const now = new Date().toISOString();

  const seeds = [
    // MEATSOURCE
    { content: 'Pork margin is +20% rounded up to nearest whole number. Minimum ₱20/kg non-negotiable.', scope: 'meatsource' },
    { content: 'Chicken margin is +15% rounded up. Minimum ₱20/kg non-negotiable.', scope: 'meatsource' },
    { content: 'Beef margin is +25% rounded up. Minimum ₱20/kg non-negotiable.', scope: 'meatsource' },
    { content: 'Fish and Fries sold at cost — zero markup.', scope: 'meatsource' },
    { content: 'Pork Belly/Liempo sold per piece, 7–10kg per piece.', scope: 'meatsource' },
    { content: '46 products across Pork, Chicken, Beef, Fish and Fries categories.', scope: 'meatsource' },
    { content: 'Facebook page: fb.com/meatsourceph. Mon/Wed/Fri content schedule.', scope: 'meatsource' },
    { content: 'GCash is primary payment. Payment-first policy always.', scope: 'meatsource' },
    // GABAY ESSENTIALS
    { content: 'Niche cluster: Tech and Gadgets (primary), Health and Wellness (primary), Beauty and Skincare (primary), Car/Motor Accessories (bonus), Office and Study (bonus).', scope: 'gabay' },
    { content: 'One-niche-first approach confirmed. Start with Tech and Gadgets.', scope: 'gabay' },
    { content: 'Platforms: TikTok, Facebook, Instagram, Shopee affiliate, Lazada affiliate, WordPress.', scope: 'gabay' },
    { content: 'TikTok Phase 1 = bio link only. Phase 2 = TikTok Shop after 1,000 followers organically. Do NOT buy account.', scope: 'gabay' },
    { content: 'All content 100% AI-generated. No manual creative work from Gerald.', scope: 'gabay' },
    { content: 'Monthly budget locked at ₱7,910–₱8,710.', scope: 'gabay' },
    { content: 'Brand name still pending — this is the only blocker for Phase 1 launch.', scope: 'gabay' },
    { content: 'Stack: Claude API, ChatGPT Plus, Gemini, Creatify, Ideogram API, Make.com, Firebase, Cloudflare Pages.', scope: 'gabay' },
    // EXIS OS
    { content: 'Exis OS tagline: Execute Your Existence. A living system — starts empty, grows through input, strengthens through repetition, validates through execution, reveals patterns over time.', scope: 'exis-os' },
    { content: 'Core law: Nothing is dismissed. Everything is captured. What you write becomes memory. What you execute becomes pattern. Patterns reveal priorities. Existence evolves through what you execute.', scope: 'exis-os' },
    { content: 'System flow: Write → Route → Continue/Memory/Done/Evidence/Keep → Signal Strength → Pattern → Insight.', scope: 'exis-os' },
    { content: 'Stack: Cloudflare Pages PWA, Firebase Auth + Firestore + Storage, Cloudflare Worker, OpenAI API primary reasoning, Claude API memory recall, Browser Speech API voice layer.', scope: 'exis-os' },
    { content: 'Capture is unlimited. Processing is limited. Energy = visible control. Quota = real enforcement. 1:1 mapping per successful processing action.', scope: 'exis-os' },
    { content: 'No manual tagging — only actions. Domains are light context only, do not define priority or importance.', scope: 'exis-os' },
    { content: 'Write is frictionless — supports text, voice (no cost), attachments (no cost). No structure forced, no validation, no blocking.', scope: 'exis-os' },
    { content: 'Signal system: Noise → Capture → Reinforced → Intent → Execution → Confirmed → Proven. Evidence is strongest signal layer — Proof beats execution.', scope: 'exis-os' },
    // GLOBAL
    { content: 'Gerald Reyes is an entrepreneur in Quezon City, Philippines running MEATSOURCE, Gabay Essentials, and Exis OS simultaneously.', scope: 'global' },
    { content: 'Emergency fund is untouchable — never include in any plan.', scope: 'global' },
    { content: 'GCash is primary payment across all businesses. Currency is always Philippine Pesos (₱).', scope: 'global' },
    { content: 'Gerald builds and maintains his own web apps using Firebase and Cloudflare Pages.', scope: 'global' },
    { content: 'All decisions already made are final — do not re-litigate them.', scope: 'global' },
    { content: 'Conservative projections always. Brutal honesty over comfortable agreement.', scope: 'global' },
  ];

  const results = [];
  for (const s of seeds) {
    const id = await db.add('memory', {
      content: s.content,
      scope: s.scope,
      tags: [],
      pinned: true,
      session_id: 'seed',
      createdAt: now,
    });
    results.push({ id, scope: s.scope });
  }

  return jsonResponse({ seeded: results.length, results, timestamp: now });
}

// GET /review — returns all pending memory_updates proposals
async function handleReview(request, env) {
  const { authError } = await requireAuth(request, env);
  if (authError) return authError;

  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit')) || 100, 200);

  const db = await initFirestore(env);
  const items = await db.query('', 'memory_updates', {
    filters: [{
      fieldFilter: {
        field: { fieldPath: 'status' },
        op: 'EQUAL',
        value: { stringValue: 'pending' },
      },
    }],
    orderBy: { field: 'proposed_at', direction: 'DESCENDING' },
    limit,
  });

  return jsonResponse({ count: items.length, items });
}

// POST /admin/approve-memory — moves an approved proposal into the stable memory collection
async function handleApproveMemory(request, env) {
  const { authError } = await requireAuth(request, env);
  if (authError) return authError;

  let body;
  try { body = await request.json(); } catch { return errorResponse('Invalid JSON body'); }

  const { id } = body;
  if (!id || typeof id !== 'string') return errorResponse('id (string) is required');

  const db = await initFirestore(env);

  const proposal = await db.get('memory_updates', id);
  if (!proposal) return errorResponse('Proposal not found', 404);
  if (proposal.status !== 'pending') return errorResponse(`Proposal is already ${proposal.status}`, 409);

  const now = new Date().toISOString();

  // Write to stable memory
  const memId = await db.add('memory', {
    content:     proposal.content,
    scope:       proposal.scope   || 'global',
    tags:        proposal.tags    || [],
    pinned:      proposal.pinned  || false,
    session_id:  proposal.session_id || null,
    confidence:  proposal.confidence || 0.8,
    source_id:   id,
    createdAt:   now,
    user_id:     proposal.user_id || null,
  });

  // Mark proposal as approved
  await db.set('memory_updates', id, { ...proposal, status: 'approved', approved_at: now, memory_id: memId });

  // Phase 9: Invalidate scope cache so next request loads fresh memory
  invalidateScopeCache(proposal.scope || 'global');

  return jsonResponse({ id: memId, source_id: id, collection: 'memory', action: 'approved' });
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return corsPreflightResponse();

    const { pathname } = new URL(request.url);
    const method = request.method;

    try {
      if (pathname === '/health'            && method === 'GET')  return await handleHealth();
      if (pathname === '/config'            && method === 'GET')  return await handleConfig(env);
      if (pathname === '/active-session'    && method === 'GET')  return await handleActiveSession(request, env);
      if (pathname === '/summarize-session' && method === 'POST') return await handleSummarizeSession(request, env);
      if (pathname === '/chat'              && method === 'POST') return await handleChat(request, env, ctx);
      if (pathname === '/recall' && method === 'GET')  return await handleRecallMemory(request, env);
      if (pathname === '/recall' && method === 'POST') return await handleRecall(request, env);
      if (pathname === '/import' && method === 'POST') return await handleImport(request, env);
      if (pathname === '/save'   && method === 'POST') return await handleSave(request, env);
      if (pathname === '/review' && method === 'GET')  return await handleReview(request, env);
      if (pathname === '/admin/approve-memory' && method === 'POST') return await handleApproveMemory(request, env);
      if (pathname === '/admin/seed' && method === 'POST') return await handleAdminSeed(request, env);
      if (pathname === '/admin/seed-memory' && method === 'POST') return await handleAdminSeedMemory(request, env);
      if (pathname === '/admin/memory' && method === 'GET') return await handleAdminMemory(request, env);

      return errorResponse('Not found', 404);
    } catch (err) {
      console.error('[ge-ai] Unhandled error:', err?.message ?? err);
      return errorResponse('Internal server error', 500);
    }
  },
};
