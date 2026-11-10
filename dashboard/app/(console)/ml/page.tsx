"use client"

import * as React from "react"
import { RefreshCwIcon } from "lucide-react"
import { Bar, BarChart, CartesianGrid, ReferenceLine, XAxis, YAxis } from "recharts"
import { toast } from "sonner"

import { ActionBadge, EmptyState, ErrorNotice, HealthBadge, LastUpdated, LoadingRows, SimulatedTag } from "@/components/waf/shared"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { apiSend, useLive } from "@/lib/api"
import { formatDateTime, formatNumber } from "@/lib/format"
import type { MlStatus, Page, RequestRow } from "@/lib/types"

const chartConfig = { count: { label: "Requests", color: "var(--series-allowed)" } } satisfies ChartConfig

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="text-sm font-medium tabular-nums">{children}</span>
    </div>
  )
}

export default function MlPage() {
  const status = useLive<MlStatus>("/ml/status", 10000)
  const anomalies = useLive<Page<RequestRow>>("/ml/anomalies?limit=50", 5000)
  const [busy, setBusy] = React.useState(false)
  const model = status.data
  const active = model?.history.find((run) => run.active)
  const threshold = model?.threshold_override ?? model?.threshold ?? null

  async function retrain(source: "generated" | "observed") {
    setBusy(true)
    try {
      const result = await apiSend<{ samples: number }>("POST", "/ml/retrain", { source })
      toast.success(`Model retrained on ${formatNumber(result.samples)} requests`)
      status.refresh()
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Training failed")
    }
    setBusy(false)
  }

  const histogram = (model?.score_distribution ?? []).map((row) => ({ ...row, label: row.from.toFixed(3) }))
  const thresholdBar = threshold === null ? undefined : histogram.find((row) => threshold >= row.from && threshold < row.to)?.label

  return (
    <>
      <Alert>
        <AlertTitle>How to read this page</AlertTitle>
        <AlertDescription>
          Isolation Forest scores how unusual a request looks compared with normal traffic. A flag is supporting evidence, not proof of an attack, so by default flagged requests still reach the website.
        </AlertDescription>
      </Alert>

      <ErrorNotice message={status.error ?? anomalies.error} />

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-3">
          <div className="flex flex-col gap-1">
            <CardTitle>Model status</CardTitle>
            <CardDescription>The trained model currently scoring traffic</CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" disabled={busy} onClick={() => retrain("generated")}>
              <RefreshCwIcon />
              Retrain (simulated)
            </Button>
            <Button variant="outline" size="sm" disabled={busy} onClick={() => retrain("observed")}>
              <RefreshCwIcon />
              Retrain (with real traffic)
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {!model ? (
            <LoadingRows rows={2} />
          ) : (
            <div className="grid grid-cols-2 gap-4 @3xl/main:grid-cols-3 @6xl/main:grid-cols-6">
              <Fact label="State"><HealthBadge ok={model.loaded} good="Loaded" bad={model.error ?? "Not loaded"} /></Fact>
              <Fact label="Scoring">{model.enabled ? "On" : "Off"}</Fact>
              <Fact label="When flagged">{model.block_on_anomaly ? "Block request" : "Log only"}</Fact>
              <Fact label="Alert threshold">{threshold?.toFixed(4) ?? "—"}</Fact>
              <Fact label="Training requests">{active ? formatNumber(active.samples) : "—"}</Fact>
              <Fact label="Held-out flag rate">{active ? `${(active.holdout_flag_rate * 100).toFixed(2)}%` : "—"}</Fact>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Anomaly scores, last 24 hours</CardTitle>
          <CardDescription>Number of requests at each score. Requests at or above the threshold are flagged.</CardDescription>
        </CardHeader>
        <CardContent>
          {histogram.length ? (
            <ChartContainer config={chartConfig} className="aspect-auto h-56 w-full">
              <BarChart data={histogram} margin={{ top: 16, right: 8, left: 0 }}>
                <CartesianGrid vertical={false} stroke="var(--series-grid)" />
                <XAxis dataKey="label" tickLine={false} axisLine={false} minTickGap={24} />
                <YAxis width={44} allowDecimals={false} tickLine={false} axisLine={false} />
                <ChartTooltip cursor={false} content={<ChartTooltipContent hideIndicator labelFormatter={(value) => `Score from ${value}`} />} />
                {thresholdBar ? (
                  <ReferenceLine x={thresholdBar} stroke="var(--foreground)" strokeDasharray="4 4" label={{ value: "Threshold", position: "top", fill: "var(--foreground)", fontSize: 12 }} />
                ) : null}
                <Bar dataKey="count" fill="var(--color-count)" radius={[4, 4, 0, 0]} isAnimationActive={false} />
              </BarChart>
            </ChartContainer>
          ) : (
            <EmptyState title="No scored requests in the last 24 hours" />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <div className="flex flex-col gap-1">
            <CardTitle>Flagged requests</CardTitle>
            <CardDescription>Requests scored above the threshold</CardDescription>
          </div>
          <LastUpdated at={anomalies.updatedAt} />
        </CardHeader>
        <CardContent className="px-0">
          {anomalies.loading && !anomalies.data ? (
            <LoadingRows />
          ) : anomalies.data?.items.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-4">Time</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Request</TableHead>
                  <TableHead className="text-right">Score</TableHead>
                  <TableHead className="pr-4">Result</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {anomalies.data.items.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell className="pl-4 whitespace-nowrap text-muted-foreground">{formatDateTime(row.created_at)}</TableCell>
                    <TableCell className="whitespace-nowrap font-mono text-xs">
                      {row.client_ip} <SimulatedTag simulated={row.simulated} />
                    </TableCell>
                    <TableCell className="max-w-96 truncate font-mono text-xs" title={`${row.method} ${row.path}`}>
                      <span className="font-semibold">{row.method}</span> {row.path}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{row.anomaly_score?.toFixed(3)}</TableCell>
                    <TableCell className="pr-4">
                      <ActionBadge action={row.action} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <EmptyState title="No flagged requests yet">Run the Anomaly scenario in the attack simulator to see the model respond.</EmptyState>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Training history</CardTitle>
          <CardDescription>Each model trained, and how often it flagged normal traffic it had never seen</CardDescription>
        </CardHeader>
        <CardContent className="px-0">
          {model?.history.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-4">Trained</TableHead>
                  <TableHead>Data</TableHead>
                  <TableHead className="text-right">Requests</TableHead>
                  <TableHead className="text-right">Threshold</TableHead>
                  <TableHead className="text-right">Flag rate</TableHead>
                  <TableHead>By</TableHead>
                  <TableHead className="pr-4">State</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {model.history.map((run) => (
                  <TableRow key={run.id}>
                    <TableCell className="pl-4 whitespace-nowrap text-muted-foreground">{formatDateTime(run.created_at)}</TableCell>
                    <TableCell>{run.source === "observed" ? "Simulated + real" : "Simulated"}</TableCell>
                    <TableCell className="text-right tabular-nums">{formatNumber(run.samples)}</TableCell>
                    <TableCell className="text-right tabular-nums">{run.threshold.toFixed(4)}</TableCell>
                    <TableCell className="text-right tabular-nums">{(run.holdout_flag_rate * 100).toFixed(2)}%</TableCell>
                    <TableCell>{run.trained_by ?? "—"}</TableCell>
                    <TableCell className="pr-4">{run.active ? "Active" : "Replaced"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <EmptyState title="No training history recorded" />
          )}
        </CardContent>
      </Card>
    </>
  )
}
