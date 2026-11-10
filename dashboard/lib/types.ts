export type Incident = {
  id: string
  created_at: string
  client_ip: string
  method: string
  path: string
  attack_type: string
  severity: "low" | "medium" | "high" | "critical"
  rule_id: string | null
  rule_name: string | null
  location: string | null
  evidence: string | null
  action_taken: "blocked" | "logged"
  anomaly_score: number | null
  mode: string
  status: "open" | "reviewed" | "false_positive"
  simulated: boolean
}

export type RequestRow = {
  id: string
  created_at: string
  client_ip: string
  method: string
  path: string
  query: string | null
  user_agent: string | null
  status_code: number
  action: "allowed" | "flagged" | "blocked" | "rate_limited" | "banned" | "error"
  reason: string | null
  waf_ms: number
  upstream_ms: number | null
  anomaly_score: number | null
  is_anomaly: boolean
  mode: string
  simulated: boolean
}

export type Page<T> = { items: T[]; next_before_id: string | null }

export type Overview = {
  window: string
  bucket_seconds: number
  totals: {
    requests: number
    allowed: number
    flagged: number
    blocked: number
    rate_limited: number
    banned: number
    errors: number
    anomalies: number
    unique_ips: number
    incidents: number
  }
  latency: { waf_p50_ms: number | null; waf_p95_ms: number | null }
  series: { t: string; allowed: number; blocked: number; anomalies: number }[]
  incidents_by_type: { type: string; count: number }[]
  incidents_by_severity: { severity: string; count: number }[]
  top_ips: { ip: string; count: number }[]
  recent_incidents: Incident[]
  active_bans: number
  mode: string
}

export type Ban = {
  id: number
  ip: string
  reason: string
  source: "auto" | "manual"
  created_by: string | null
  created_at: string
  expires_at: string | null
  lifted_at: string | null
  lifted_by: string | null
  simulated: boolean
  active: boolean
}

export type WafConfig = {
  mode: "block" | "monitor"
  rate_limit_per_minute: number
  ban_minutes: number
  strikes_before_ban: number
  ml_enabled: boolean
  ml_block: boolean
  ml_threshold_override: number | null
  ip_allowlist: string[]
}

export type WafSettings = {
  config: WafConfig
  environment: {
    waf_env: string
    upstream_url: string
    fail_mode: string
    trust_proxy_hops: number
    max_body_bytes: number
    log_retention_days: number
    simulator_enabled: boolean
  }
}

export type MlStatus = {
  loaded: boolean
  error: string | null
  enabled: boolean
  block_on_anomaly: boolean
  threshold: number | null
  threshold_override: number | null
  feature_names: string[]
  history: {
    id: number
    created_at: string
    source: string
    samples: number
    threshold: number
    holdout_flag_rate: number
    trained_by: string | null
    active: boolean
  }[]
  score_distribution: { from: number; to: number; count: number }[]
}

export type Health = {
  status: "healthy" | "degraded"
  uptime_seconds: number
  environment: string
  mode: string
  requests_since_start: number
  database: { ok: boolean; latency_ms: number | null; error: string | null }
  upstream: { ok: boolean; url: string; status: number | null; latency_ms: number | null; error: string | null }
  ml: { loaded: boolean; enabled: boolean; error: string | null; failures: number }
  log_writer: { pending: number; written: number; dropped: number; failures: number; last_error: string | null }
  inspection_errors: number
  upstream_errors: number
  active_bans: number
}

export type AuditEntry = {
  id: string
  created_at: string
  username: string
  action: string
  target: string | null
  details: Record<string, unknown> | null
  ip: string | null
}

export type SimulationResult = {
  scenario: string
  simulated_ip: string
  target: string
  requests: number
  blocked: number
  forwarded: number
  results: { method: string; path: string; status: number }[]
}

export type PlaygroundWhere = "query" | "path" | "form" | "json" | "header" | "cookie"

export type PlaygroundFinding = {
  rule_id: string
  rule_name: string
  attack: string
  severity: string
  location: string
  evidence: string
}

export type PlaygroundResult = {
  verdict: "attack" | "suspicious" | "clean"
  action: string
  mode: string
  request: { method: string; url: string; headers: Record<string, string>; body: string }
  findings: PlaygroundFinding[]
  decoding: {
    rounds: string[]
    normalized: string
    compact: string
    base64: string | null
    base64_normalized: string | null
    base64_compact: string | null
    matches: { rule_id: string; variant: "text" | "base64"; form: "normal" | "compact"; start: number; end: number }[]
  }
  ml: {
    available: boolean
    score?: number
    normal_score?: number
    threshold?: number
    is_anomaly?: boolean
    changed_features?: { name: string; value: number; normal: number }[]
    ms?: number
  }
  signature_ms: number
}
