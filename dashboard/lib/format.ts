const dateTime = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
})

export function formatDateTime(value: string | null | undefined): string {
  return value ? dateTime.format(new Date(value)) : "—"
}

export function formatMs(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—"
  return value < 10 ? `${value.toFixed(1)} ms` : `${Math.round(value)} ms`
}

export function formatNumber(value: number): string {
  return value.toLocaleString()
}

export function formatDuration(seconds: number): string {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (days) return `${days}d ${hours}h`
  if (hours) return `${hours}h ${minutes}m`
  if (minutes) return `${minutes}m ${seconds % 60}s`
  return `${seconds}s`
}

const ATTACK_LABELS: Record<string, string> = {
  sqli: "SQL injection",
  xss: "Cross-site scripting",
  evasion: "Evasion attempt",
  anomaly: "ML anomaly",
  rate_limit: "Rate limit",
  banned_ip: "Banned IP",
  inspection_error: "Inspection error",
}

export function attackLabel(type: string): string {
  return ATTACK_LABELS[type] ?? type
}
