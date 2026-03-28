import { Hono } from 'hono';
import { cors } from 'hono/cors';

type Env = {
  DB: D1Database;
  CACHE: KVNamespace;
  ENGINE_RUNTIME: Fetcher;
  ECHO_API_KEY: string;
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  ANALYTICS: AnalyticsEngineDataset;
};

const SURVEY_PLANS = [
  { id: 'free', name: 'Free', surveys: 10, responses: 500, price: 0, display: 'Free' },
  { id: 'pro', name: 'Pro', surveys: 100, responses: 25000, price: 2999, display: '$29.99/mo' },
  { id: 'business', name: 'Business', surveys: 1000, responses: 250000, price: 7999, display: '$79.99/mo' },
  { id: 'enterprise', name: 'Enterprise', surveys: -1, responses: -1, price: 19999, display: '$199.99/mo' },
] as const;

async function verifyStripeSignature(payload: string, sigHeader: string, secret: string): Promise<boolean> {
  const parts: Record<string, string> = {};
  for (const p of sigHeader.split(',')) { const eq = p.indexOf('='); if (eq > 0) parts[p.slice(0, eq).trim()] = p.slice(eq + 1).trim(); }
  const ts = parts['t'], v1 = parts['v1'];
  if (!ts || !v1 || Math.abs(Date.now() / 1000 - parseInt(ts)) > 300) return false;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${ts}.${payload}`));
  const expected = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  if (expected.length !== v1.length) return false;
  let diff = 0; for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ v1.charCodeAt(i);
  return diff === 0;
}

const app = new Hono<{ Bindings: Env }>();
// Security headers middleware
app.use('*', async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('X-XSS-Protection', '1; mode=block');
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});

app.use('*', cors());

function uid(): string { return crypto.randomUUID(); }
function sanitize(s: unknown, max = 5000): string {
  if (typeof s !== 'string') return '';
  return s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').slice(0, max);
}
function sanitizeBody(b: Record<string, unknown>): Record<string, unknown> {
  const o: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(b)) o[k] = typeof v === 'string' ? sanitize(v) : v;
  return o;
}
function tid(c: any): string { return sanitize(c.req.header('X-Tenant-ID') || c.req.query('tenant_id') || '', 100); }
function json(c: any, d: unknown, s = 200) { return c.json(d, s); }

function slog(level: 'info' | 'warn' | 'error', msg: string, data?: Record<string, unknown>) {
  const entry = { ts: new Date().toISOString(), level, worker: 'echo-surveys', version: '2.0.0', msg, ...data };
  if (level === 'error') console.error(JSON.stringify(entry));
  else console.log(JSON.stringify(entry));
}


interface RLState { c: number; t: number }
async function rateLimit(env: Env, key: string, max: number, windowSec = 60): Promise<boolean> {
  const k = `rl:${key}`;
  const now = Date.now();
  const raw = await env.CACHE.get(k);
  let st: RLState = raw ? JSON.parse(raw) : { c: 0, t: now };
  const elapsed = (now - st.t) / 1000;
  const decay = Math.floor(elapsed * (max / windowSec));
  st.c = Math.max(0, st.c - decay);
  st.t = now;
  if (st.c >= max) return false;
  st.c++;
  await env.CACHE.put(k, JSON.stringify(st), { expirationTtl: windowSec * 2 });
  return true;
}

// Auth — public submit endpoints exempt
app.use('*', async (c, next) => {
  const path = c.req.path;
  if (path === '/health' || path === '/status' || path.startsWith('/s/') || path.startsWith('/submit/') || path === '/webhooks/stripe' || c.req.method === 'GET') return next();
  const key = c.req.header('X-Echo-API-Key') || c.req.header('Authorization')?.replace('Bearer ', '');
  if (!key || key !== c.env.ECHO_API_KEY) return json(c, { error: 'Unauthorized' }, 401);
  return next();
});

// Rate limiting
app.use('*', async (c, next) => {
  const path = c.req.path;
  if (path === '/health' || path === '/status') return next();
  const ip = c.req.header('CF-Connecting-IP') || 'unknown';
  const isSubmit = path.startsWith('/submit/');
  const max = isSubmit ? 30 : (c.req.method === 'GET' ? 200 : 60);
  if (!await rateLimit(c.env, `${ip}:${isSubmit ? 'submit' : c.req.method}`, max)) return json(c, { error: 'Rate limited' }, 429);
  return next();
});

// Health
app.get('/', (c) => json(c, { service: 'echo-surveys', version: '2.0.0', status: 'operational' }));
app.get('/health', (c) => json(c, { status: 'ok', service: 'echo-surveys', version: '2.0.0', timestamp: new Date().toISOString() }));
app.get('/status', (c) => json(c, { status: 'operational', service: 'echo-surveys', version: '2.0.0' }));

// === STRIPE WEBHOOK ===
app.post('/webhooks/stripe', async (c) => {
  if (!c.env.STRIPE_WEBHOOK_SECRET) return json(c, { error: 'Not configured' }, 503);
  const body = await c.req.text();
  const sig = c.req.header('Stripe-Signature') || '';
  if (!(await verifyStripeSignature(body, sig, c.env.STRIPE_WEBHOOK_SECRET))) return json(c, { error: 'Invalid signature' }, 401);
  const event = JSON.parse(body);
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const tenantId = session.metadata?.tenant_id;
    const plan = session.metadata?.plan;
    if (tenantId && plan) {
      const planDef = SURVEY_PLANS.find(p => p.id === plan);
      if (planDef) {
        await c.env.DB.prepare('UPDATE tenants SET plan=?, max_surveys=?, max_responses_month=?, stripe_customer_id=?, plan_expires_at=datetime("now","+30 days") WHERE id=?')
          .bind(plan, planDef.surveys, planDef.responses, session.customer || null, tenantId).run();
        slog('info', 'Plan upgraded via Stripe', { tenant_id: tenantId, plan });
      }
    }
  }
  return json(c, { received: true });
});

// === PLANS ===
app.get('/plans', async (c) => {
  const t = tid(c);
  const tenant = await c.env.DB.prepare('SELECT plan, max_surveys, max_responses_month, plan_expires_at FROM tenants WHERE id=?').bind(t).first();
  return json(c, { current: tenant?.plan || 'free', limits: { surveys: tenant?.max_surveys, responses: tenant?.max_responses_month }, expires: tenant?.plan_expires_at, plans: SURVEY_PLANS });
});

app.post('/plans/upgrade', async (c) => {
  if (!c.env.STRIPE_SECRET_KEY) return json(c, { error: 'Stripe not configured' }, 503);
  const b = await c.req.json<{ plan: string; success_url?: string; cancel_url?: string }>().catch(() => null);
  if (!b?.plan) return json(c, { error: 'plan required' }, 400);
  const plan = SURVEY_PLANS.find(p => p.id === b.plan && p.price > 0);
  if (!plan) return json(c, { error: 'Invalid plan' }, 400);
  const t = tid(c);
  const base = 'https://echo-surveys.bmcii1976.workers.dev';
  const params = new URLSearchParams({
    'mode': 'subscription',
    'success_url': b.success_url || `${base}/health?upgraded=true`,
    'cancel_url': b.cancel_url || base,
    'line_items[0][price_data][currency]': 'usd',
    'line_items[0][price_data][product_data][name]': `Echo Surveys — ${plan.name} Plan`,
    'line_items[0][price_data][unit_amount]': String(plan.price),
    'line_items[0][price_data][recurring][interval]': 'month',
    'line_items[0][quantity]': '1',
    'metadata[tenant_id]': t,
    'metadata[plan]': plan.id,
  });
  const resp = await fetch('https://api.stripe.com/v1/checkout/sessions', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${c.env.STRIPE_SECRET_KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
  const session = await resp.json() as Record<string, unknown>;
  if (!resp.ok) return json(c, { error: 'Stripe error', details: session }, 502);
  return json(c, { checkout_url: session.url, session_id: session.id, plan: plan.id, price: plan.display });
});

// === TENANTS ===
app.post('/tenants', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json()) as any;
    const id = uid();
    await c.env.DB.prepare('INSERT INTO tenants (id,name,email,plan,max_surveys,max_responses_month) VALUES (?,?,?,?,?,?)').bind(id, b.name, b.email || null, b.plan || 'free', b.max_surveys || 10, b.max_responses_month || 500).run();
    return json(c, { id }, 201);
  } catch (err: any) {
    slog('error', 'Failed to create tenant', { error: err.message });
    return json(c, { error: 'Failed to create tenant', detail: err.message }, 500);
  }
});

// === SURVEYS ===
app.get('/surveys', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  try {
    const status = c.req.query('status');
    const type = c.req.query('type');
    let q = 'SELECT * FROM surveys WHERE tenant_id=?';
    const params: string[] = [t];
    if (status) { q += ' AND status=?'; params.push(status); }
    if (type) { q += ' AND type=?'; params.push(type); }
    q += ' ORDER BY created_at DESC';
    const r = await c.env.DB.prepare(q).bind(...params).all();
    return json(c, { surveys: r.results });
  } catch (err: any) {
    slog('error', 'Failed to list surveys', { error: err.message });
    return json(c, { error: 'Failed to list surveys', detail: err.message }, 500);
  }
});
app.get('/surveys/:id', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM surveys WHERE id=?').bind(c.req.param('id')).first();
    return r ? json(c, r) : json(c, { error: 'Not found' }, 404);
  } catch (err: any) {
    slog('error', 'Failed to get survey', { error: err.message });
    return json(c, { error: 'Failed to get survey', detail: err.message }, 500);
  }
});
app.post('/surveys', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  try {
    const b = sanitizeBody(await c.req.json()) as any;
    const tenant = await c.env.DB.prepare('SELECT max_surveys FROM tenants WHERE id=?').bind(t).first<any>();
    if (tenant) {
      const cnt = await c.env.DB.prepare('SELECT COUNT(*) as c FROM surveys WHERE tenant_id=?').bind(t).first<any>();
      if (cnt && cnt.c >= tenant.max_surveys) return json(c, { error: 'Survey limit reached' }, 403);
    }
    const id = uid();
    const slug = b.slug || b.title?.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || id;
    await c.env.DB.prepare('INSERT INTO surveys (id,tenant_id,title,description,type,questions_json,settings_json,theme_json,slug,is_anonymous,require_email,thank_you_message,redirect_url,start_date,end_date) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(id, t, b.title, b.description || null, b.type || 'custom', JSON.stringify(b.questions || []), JSON.stringify(b.settings || {}), JSON.stringify(b.theme || {}), slug, b.is_anonymous ? 1 : 0, b.require_email ? 1 : 0, b.thank_you_message || 'Thank you for your feedback!', b.redirect_url || null, b.start_date || null, b.end_date || null).run();
    return json(c, { id, slug }, 201);
  } catch (err: any) {
    slog('error', 'Failed to create survey', { error: err.message });
    return json(c, { error: 'Failed to create survey', detail: err.message }, 500);
  }
});
app.put('/surveys/:id', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json()) as any;
    await c.env.DB.prepare('UPDATE surveys SET title=COALESCE(?,title),description=COALESCE(?,description),questions_json=COALESCE(?,questions_json),settings_json=COALESCE(?,settings_json),theme_json=COALESCE(?,theme_json),is_anonymous=COALESCE(?,is_anonymous),thank_you_message=COALESCE(?,thank_you_message),updated_at=datetime(\'now\') WHERE id=?').bind(b.title || null, b.description || null, b.questions ? JSON.stringify(b.questions) : null, b.settings ? JSON.stringify(b.settings) : null, b.theme ? JSON.stringify(b.theme) : null, b.is_anonymous !== undefined ? (b.is_anonymous ? 1 : 0) : null, b.thank_you_message || null, c.req.param('id')).run();
    return json(c, { updated: true });
  } catch (err: any) {
    slog('error', 'Failed to update survey', { error: err.message });
    return json(c, { error: 'Failed to update survey', detail: err.message }, 500);
  }
});
app.post('/surveys/:id/publish', async (c) => {
  try {
    await c.env.DB.prepare("UPDATE surveys SET status='active',updated_at=datetime('now') WHERE id=?").bind(c.req.param('id')).run();
    return json(c, { published: true });
  } catch (err: any) {
    slog('error', 'Failed to publish survey', { error: err.message });
    return json(c, { error: 'Failed to publish survey', detail: err.message }, 500);
  }
});
app.post('/surveys/:id/close', async (c) => {
  try {
    await c.env.DB.prepare("UPDATE surveys SET status='closed',updated_at=datetime('now') WHERE id=?").bind(c.req.param('id')).run();
    return json(c, { closed: true });
  } catch (err: any) {
    slog('error', 'Failed to close survey', { error: err.message });
    return json(c, { error: 'Failed to close survey', detail: err.message }, 500);
  }
});
app.delete('/surveys/:id', async (c) => {
  try {
    await c.env.DB.prepare('DELETE FROM surveys WHERE id=?').bind(c.req.param('id')).run();
    return json(c, { deleted: true });
  } catch (err: any) {
    slog('error', 'Failed to delete survey', { error: err.message });
    return json(c, { error: 'Failed to delete survey', detail: err.message }, 500);
  }
});

// === NPS PRESETS ===
app.post('/surveys/nps', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  try {
    const b = sanitizeBody(await c.req.json()) as any;
    const id = uid();
    const questions = [
      { id: 'nps', type: 'nps', text: b.question || 'How likely are you to recommend us to a friend or colleague?', required: true },
      { id: 'reason', type: 'text', text: 'What is the primary reason for your score?', required: false },
    ];
    const slug = `nps-${Date.now().toString(36)}`;
    await c.env.DB.prepare('INSERT INTO surveys (id,tenant_id,title,description,type,questions_json,slug,is_anonymous) VALUES (?,?,?,?,?,?,?,?)').bind(id, t, b.title || 'NPS Survey', b.description || 'Net Promoter Score survey', 'nps', JSON.stringify(questions), slug, b.is_anonymous ? 1 : 0).run();
    return json(c, { id, slug }, 201);
  } catch (err: any) {
    slog('error', 'Failed to create NPS survey', { error: err.message });
    return json(c, { error: 'Failed to create NPS survey', detail: err.message }, 500);
  }
});
app.post('/surveys/csat', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  try {
    const b = sanitizeBody(await c.req.json()) as any;
    const id = uid();
    const questions = [
      { id: 'csat', type: 'rating', text: b.question || 'How satisfied are you with our service?', scale: 5, required: true },
      { id: 'feedback', type: 'text', text: 'Any additional feedback?', required: false },
    ];
    const slug = `csat-${Date.now().toString(36)}`;
    await c.env.DB.prepare('INSERT INTO surveys (id,tenant_id,title,description,type,questions_json,slug,is_anonymous) VALUES (?,?,?,?,?,?,?,?)').bind(id, t, b.title || 'CSAT Survey', b.description || 'Customer satisfaction survey', 'csat', JSON.stringify(questions), slug, b.is_anonymous ? 1 : 0).run();
    return json(c, { id, slug }, 201);
  } catch (err: any) {
    slog('error', 'Failed to create CSAT survey', { error: err.message });
    return json(c, { error: 'Failed to create CSAT survey', detail: err.message }, 500);
  }
});

// === PUBLIC SURVEY ACCESS ===
app.get('/s/:slug', async (c) => {
  try {
    const survey = await c.env.DB.prepare("SELECT * FROM surveys WHERE slug=? AND status='active'").bind(c.req.param('slug')).first<any>();
    if (!survey) return json(c, { error: 'Survey not found or inactive' }, 404);
    if (survey.end_date && new Date(survey.end_date) < new Date()) return json(c, { error: 'Survey has ended' }, 410);
    return json(c, { survey: { id: survey.id, title: survey.title, description: survey.description, type: survey.type, questions: JSON.parse(survey.questions_json), theme: JSON.parse(survey.theme_json), is_anonymous: survey.is_anonymous, require_email: survey.require_email } });
  } catch (err: any) {
    slog('error', 'Failed to load public survey', { error: err.message });
    return json(c, { error: 'Failed to load survey', detail: err.message }, 500);
  }
});

// === SUBMIT RESPONSE (public) ===
app.post('/submit/:surveyId', async (c) => {
  try {
    const surveyId = c.req.param('surveyId');
    const survey = await c.env.DB.prepare("SELECT * FROM surveys WHERE id=? AND status='active'").bind(surveyId).first<any>();
    if (!survey) return json(c, { error: 'Survey not found or inactive' }, 404);
    const b = sanitizeBody(await c.req.json()) as any;
    const answers = b.answers || {};
    const id = uid();

    // Calculate score for NPS/CSAT
    let score: number | null = null;
    let npsCategory: string | null = null;
    if (survey.type === 'nps' && answers.nps !== undefined) {
      score = parseInt(answers.nps) || 0;
      npsCategory = score >= 9 ? 'promoter' : score >= 7 ? 'passive' : 'detractor';
    } else if (survey.type === 'csat' && answers.csat !== undefined) {
      score = parseFloat(answers.csat) || 0;
    }

    await c.env.DB.prepare('INSERT INTO responses (id,survey_id,tenant_id,respondent_email,respondent_name,answers_json,score,nps_category,completion_time_sec,ip_address,user_agent,metadata_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)').bind(id, surveyId, survey.tenant_id, b.email || null, b.name || null, JSON.stringify(answers), score, npsCategory, b.completion_time_sec || 0, c.req.header('CF-Connecting-IP') || '', c.req.header('User-Agent') || '', JSON.stringify(b.metadata || {})).run();

    await c.env.DB.prepare('UPDATE surveys SET response_count=response_count+1,updated_at=datetime(\'now\') WHERE id=?').bind(surveyId).run();

    // Update avg_score if scored
    if (score !== null) {
      const avg = await c.env.DB.prepare('SELECT AVG(score) as a FROM responses WHERE survey_id=? AND score IS NOT NULL').bind(surveyId).first<any>();
      await c.env.DB.prepare('UPDATE surveys SET avg_score=? WHERE id=?').bind(avg?.a || 0, surveyId).run();
    }

    return json(c, { id, thank_you: survey.thank_you_message, redirect_url: survey.redirect_url }, 201);
  } catch (err: any) {
    slog('error', 'Failed to submit response', { error: err.message });
    return json(c, { error: 'Failed to submit response', detail: err.message }, 500);
  }
});

// === RESPONSES ===
app.get('/surveys/:sid/responses', async (c) => {
  try {
    const page = parseInt(c.req.query('page') || '1');
    const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
    const offset = (page - 1) * limit;
    const r = await c.env.DB.prepare('SELECT * FROM responses WHERE survey_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?').bind(c.req.param('sid'), limit, offset).all();
    const total = await c.env.DB.prepare('SELECT COUNT(*) as c FROM responses WHERE survey_id=?').bind(c.req.param('sid')).first<any>();
    return json(c, { responses: r.results, total: total?.c || 0, page, limit });
  } catch (err: any) {
    slog('error', 'Failed to list responses', { error: err.message });
    return json(c, { error: 'Failed to list responses', detail: err.message }, 500);
  }
});
app.get('/responses/:id', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM responses WHERE id=?').bind(c.req.param('id')).first();
    return r ? json(c, r) : json(c, { error: 'Not found' }, 404);
  } catch (err: any) {
    slog('error', 'Failed to get response', { error: err.message });
    return json(c, { error: 'Failed to get response', detail: err.message }, 500);
  }
});

// === ANALYTICS ===
app.get('/analytics/overview', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  try {
    const [surveys, active, responses, avgNps] = await Promise.all([
      c.env.DB.prepare('SELECT COUNT(*) as c FROM surveys WHERE tenant_id=?').bind(t).first<any>(),
      c.env.DB.prepare("SELECT COUNT(*) as c FROM surveys WHERE tenant_id=? AND status='active'").bind(t).first<any>(),
      c.env.DB.prepare('SELECT COUNT(*) as c FROM responses WHERE tenant_id=?').bind(t).first<any>(),
      c.env.DB.prepare("SELECT AVG(score) as avg FROM responses WHERE tenant_id=? AND nps_category IS NOT NULL").bind(t).first<any>(),
    ]);
    return json(c, {
      total_surveys: surveys?.c || 0,
      active_surveys: active?.c || 0,
      total_responses: responses?.c || 0,
      avg_nps_score: Math.round((avgNps?.avg || 0) * 10) / 10,
    });
  } catch (err: any) {
    slog('error', 'Failed to get analytics overview', { error: err.message });
    return json(c, { error: 'Failed to get analytics overview', detail: err.message }, 500);
  }
});
app.get('/analytics/survey/:sid', async (c) => {
  try {
    const sid = c.req.param('sid');
    const survey = await c.env.DB.prepare('SELECT * FROM surveys WHERE id=?').bind(sid).first<any>();
    if (!survey) return json(c, { error: 'Not found' }, 404);
    const questions = JSON.parse(survey.questions_json || '[]');
    const responseCount = await c.env.DB.prepare('SELECT COUNT(*) as c FROM responses WHERE survey_id=?').bind(sid).first<any>();
    const result: any = { survey_id: sid, title: survey.title, type: survey.type, total_responses: responseCount?.c || 0, avg_score: survey.avg_score };

    if (survey.type === 'nps') {
      const [promoters, passives, detractors] = await Promise.all([
        c.env.DB.prepare("SELECT COUNT(*) as c FROM responses WHERE survey_id=? AND nps_category='promoter'").bind(sid).first<any>(),
        c.env.DB.prepare("SELECT COUNT(*) as c FROM responses WHERE survey_id=? AND nps_category='passive'").bind(sid).first<any>(),
        c.env.DB.prepare("SELECT COUNT(*) as c FROM responses WHERE survey_id=? AND nps_category='detractor'").bind(sid).first<any>(),
      ]);
      const total = (promoters?.c || 0) + (passives?.c || 0) + (detractors?.c || 0);
      result.nps = {
        promoters: promoters?.c || 0,
        passives: passives?.c || 0,
        detractors: detractors?.c || 0,
        nps_score: total > 0 ? Math.round(((promoters?.c || 0) - (detractors?.c || 0)) / total * 100) : 0,
      };
    }

    // Response trend (last 30 days)
    const trend = await c.env.DB.prepare("SELECT DATE(created_at) as day, COUNT(*) as count FROM responses WHERE survey_id=? AND created_at > datetime('now','-30 days') GROUP BY day ORDER BY day").bind(sid).all();
    result.trend = trend.results;

    return json(c, result);
  } catch (err: any) {
    slog('error', 'Failed to get survey analytics', { error: err.message });
    return json(c, { error: 'Failed to get survey analytics', detail: err.message }, 500);
  }
});
app.get('/analytics/nps-trend', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  try {
    const r = await c.env.DB.prepare("SELECT DATE(created_at) as day, AVG(score) as avg_score, COUNT(*) as count FROM responses WHERE tenant_id=? AND nps_category IS NOT NULL AND created_at > datetime('now','-90 days') GROUP BY day ORDER BY day").bind(t).all();
    return json(c, { trend: r.results });
  } catch (err: any) {
    slog('error', 'Failed to get NPS trend', { error: err.message });
    return json(c, { error: 'Failed to get NPS trend', detail: err.message }, 500);
  }
});

// === WEBHOOKS ===
app.get('/webhooks', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  try {
    const r = await c.env.DB.prepare('SELECT * FROM webhooks WHERE tenant_id=?').bind(t).all();
    return json(c, { webhooks: r.results });
  } catch (err: any) {
    slog('error', 'Failed to list webhooks', { error: err.message });
    return json(c, { error: 'Failed to list webhooks', detail: err.message }, 500);
  }
});
app.post('/webhooks', async (c) => {
  const t = tid(c); if (!t) return json(c, { error: 'tenant required' }, 400);
  try {
    const b = sanitizeBody(await c.req.json()) as any;
    const id = uid();
    await c.env.DB.prepare('INSERT INTO webhooks (id,tenant_id,survey_id,url,events) VALUES (?,?,?,?,?)').bind(id, t, b.survey_id || null, b.url, JSON.stringify(b.events || ['response.completed'])).run();
    return json(c, { id }, 201);
  } catch (err: any) {
    slog('error', 'Failed to create webhook', { error: err.message });
    return json(c, { error: 'Failed to create webhook', detail: err.message }, 500);
  }
});

// === AI ENDPOINTS ===
app.post('/ai/generate-questions', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json()) as any;
    const resp = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ engine_id: 'MKT-01', query: `Generate ${b.count || 5} survey questions about: "${b.topic}". Survey type: ${b.type || 'customer feedback'}. Include a mix of: rating (1-5), nps (0-10), multiple choice, and open text. Return as JSON array with id, type, text, options (for choice), required (boolean).` }),
    });
    const data = await resp.json() as any;
    return json(c, { questions: data.response || data });
  } catch (err: any) {
    slog('error', 'AI generate-questions failed', { error: err.message });
    return json(c, { error: 'AI service unavailable', detail: err.message }, 503);
  }
});
app.post('/ai/analyze-feedback', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json()) as any;
    const responses = await c.env.DB.prepare('SELECT answers_json,score,nps_category FROM responses WHERE survey_id=? ORDER BY created_at DESC LIMIT 50').bind(b.survey_id).all();
    if (!responses.results?.length) return json(c, { error: 'No responses to analyze' }, 400);
    const textAnswers = responses.results.map((r: any) => {
      const ans = JSON.parse(r.answers_json || '{}');
      return Object.values(ans).filter(v => typeof v === 'string' && (v as string).length > 10).join(' | ');
    }).filter(Boolean);
    const resp = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ engine_id: 'MKT-01', query: `Analyze these ${textAnswers.length} survey responses and identify: 1) Top 3 themes, 2) Sentiment distribution (positive/neutral/negative), 3) Key insights, 4) Recommended actions. Responses: ${textAnswers.slice(0, 20).join(' || ')}` }),
    });
    const data = await resp.json() as any;
    return json(c, { analysis: data.response || data });
  } catch (err: any) {
    slog('error', 'AI analyze-feedback failed', { error: err.message });
    return json(c, { error: 'AI service unavailable', detail: err.message }, 503);
  }
});

// === ADMIN: STRIPE MIGRATION ===
app.post('/admin/migrate-stripe', async (c) => {
  const stmts = [
    c.env.DB.prepare(`ALTER TABLE tenants ADD COLUMN stripe_customer_id TEXT`),
    c.env.DB.prepare(`ALTER TABLE tenants ADD COLUMN plan_expires_at TEXT`),
  ];
  const results = [];
  for (const s of stmts) {
    try { await s.run(); results.push('OK'); }
    catch (e: any) { results.push(e.message?.includes('duplicate') || e.message?.includes('already exists') ? 'SKIP' : `ERR: ${e.message}`); }
  }
  return json(c, { migrated: true, results });
});

app.onError((err, c) => {
  if (err.message?.includes('JSON')) {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  slog('error', 'Unhandled request error', { error: err.message, stack: err.stack });
  return c.json({ error: 'Internal server error' }, 500);
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

// Scheduled cleanup
export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    try {
      await env.DB.prepare("DELETE FROM activity_log WHERE created_at < datetime('now','-90 days')").run();
      // Close expired surveys
      await env.DB.prepare("UPDATE surveys SET status='closed' WHERE status='active' AND end_date IS NOT NULL AND end_date < datetime('now')").run();
    } catch (err: any) {
      slog('error', 'Scheduled cleanup failed', { error: err.message });
    }
  },
};
