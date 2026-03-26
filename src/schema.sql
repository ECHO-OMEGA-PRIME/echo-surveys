-- Echo Surveys v1.0.0 Schema
-- AI-powered surveys, NPS, CSAT, and feedback collection

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT,
  plan TEXT DEFAULT 'free',
  max_surveys INTEGER DEFAULT 10,
  max_responses_month INTEGER DEFAULT 500,
  branding_json TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS surveys (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  type TEXT DEFAULT 'custom',
  status TEXT DEFAULT 'draft',
  questions_json TEXT NOT NULL DEFAULT '[]',
  settings_json TEXT DEFAULT '{}',
  theme_json TEXT DEFAULT '{}',
  slug TEXT,
  is_anonymous INTEGER DEFAULT 0,
  require_email INTEGER DEFAULT 0,
  thank_you_message TEXT DEFAULT 'Thank you for your feedback!',
  redirect_url TEXT,
  start_date TEXT,
  end_date TEXT,
  response_count INTEGER DEFAULT 0,
  avg_score REAL DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_survey_tenant ON surveys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_survey_slug ON surveys(slug);
CREATE INDEX IF NOT EXISTS idx_survey_status ON surveys(tenant_id, status);

CREATE TABLE IF NOT EXISTS responses (
  id TEXT PRIMARY KEY,
  survey_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  respondent_email TEXT,
  respondent_name TEXT,
  answers_json TEXT NOT NULL DEFAULT '{}',
  score REAL,
  nps_category TEXT,
  completion_time_sec INTEGER DEFAULT 0,
  ip_address TEXT,
  user_agent TEXT,
  metadata_json TEXT DEFAULT '{}',
  is_complete INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (survey_id) REFERENCES surveys(id)
);
CREATE INDEX IF NOT EXISTS idx_resp_survey ON responses(survey_id);
CREATE INDEX IF NOT EXISTS idx_resp_tenant ON responses(tenant_id);
CREATE INDEX IF NOT EXISTS idx_resp_email ON responses(respondent_email);

CREATE TABLE IF NOT EXISTS question_analytics (
  id TEXT PRIMARY KEY,
  survey_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  question_id TEXT NOT NULL,
  question_text TEXT,
  question_type TEXT,
  total_responses INTEGER DEFAULT 0,
  avg_score REAL DEFAULT 0,
  distribution_json TEXT DEFAULT '{}',
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (survey_id) REFERENCES surveys(id)
);
CREATE INDEX IF NOT EXISTS idx_qa_survey ON question_analytics(survey_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_qa_unique ON question_analytics(survey_id, question_id);

CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  survey_id TEXT,
  url TEXT NOT NULL,
  events TEXT DEFAULT '["response.completed"]',
  is_active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_webhook_tenant ON webhooks(tenant_id);

CREATE TABLE IF NOT EXISTS activity_log (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  action TEXT NOT NULL,
  actor_id TEXT,
  details TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_activity_tenant ON activity_log(tenant_id);
