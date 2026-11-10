"use client"

import { ErrorNotice, HealthBadge, LastUpdated, LoadingRows } from "@/components/waf/shared"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useLive } from "@/lib/api"
import { formatDuration, formatMs, formatNumber } from "@/lib/format"
import type { Health } from "@/lib/types"

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 border-b py-2 text-sm last:border-b-0">
      <span className="text-muted-foreground">{label}</span>
      <span className="min-w-0 truncate text-right font-medium tabular-nums">{value}</span>
    </div>
  )
}

export default function HealthPage() {
  const { data, error, updatedAt } = useLive<Health>("/health", 5000)

  return (
    <>
      <div className="flex items-center justify-between gap-3">
        {data ? <HealthBadge ok={data.status === "healthy"} good="All systems healthy" bad="Needs attention" /> : <span />}
        <LastUpdated at={updatedAt} />
      </div>

      <ErrorNotice message={error} />

      {!data ? (
        <LoadingRows rows={6} />
      ) : (
        <div className="grid gap-4 @4xl/main:grid-cols-2">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Protected website</CardTitle>
              <HealthBadge ok={data.upstream.ok} good="Reachable" bad="Unreachable" />
            </CardHeader>
            <CardContent>
              <Row label="Address" value={data.upstream.url} />
              <Row label="Response status" value={data.upstream.status ?? data.upstream.error ?? "—"} />
              <Row label="Response time" value={formatMs(data.upstream.latency_ms)} />
              <Row label="Failed forwards since start" value={formatNumber(data.upstream_errors)} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Database</CardTitle>
              <HealthBadge ok={data.database.ok} good="Connected" bad="Unavailable" />
            </CardHeader>
            <CardContent>
              <Row label="Query time" value={formatMs(data.database.latency_ms)} />
              <Row label="Logs waiting to be saved" value={formatNumber(data.log_writer.pending)} />
              <Row label="Logs saved since start" value={formatNumber(data.log_writer.written)} />
              <Row label="Logs lost since start" value={formatNumber(data.log_writer.dropped)} />
              <Row label="Failed save attempts" value={formatNumber(data.log_writer.failures)} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>ML model</CardTitle>
              <HealthBadge ok={data.ml.loaded} good="Loaded" bad="Not loaded" />
            </CardHeader>
            <CardContent>
              <Row label="Scoring" value={data.ml.enabled ? "On" : "Off"} />
              <Row label="Scoring failures since start" value={formatNumber(data.ml.failures)} />
              <Row label="Last error" value={data.ml.error ?? "None"} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>WAF process</CardTitle>
            </CardHeader>
            <CardContent>
              <Row label="Environment" value={data.environment} />
              <Row label="Mode" value={data.mode} />
              <Row label="Running for" value={formatDuration(data.uptime_seconds)} />
              <Row label="Requests since start" value={formatNumber(data.requests_since_start)} />
              <Row label="Inspection errors" value={formatNumber(data.inspection_errors)} />
              <Row label="Active bans" value={formatNumber(data.active_bans)} />
            </CardContent>
          </Card>
        </div>
      )}
    </>
  )
}
