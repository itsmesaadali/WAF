"use client"

import * as React from "react"
import { CartesianGrid, Line, LineChart, XAxis, YAxis } from "recharts"

import {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"
import type { Overview } from "@/lib/types"

const config = {
  allowed: { label: "Forwarded", color: "var(--series-allowed)" },
  blocked: { label: "Blocked", color: "var(--series-blocked)" },
  anomalies: { label: "ML anomalies", color: "var(--series-anomaly)" },
} satisfies ChartConfig

const WINDOW_SECONDS: Record<string, number> = { "1h": 3600, "24h": 86400, "7d": 604800 }

/** The API only returns time slots with traffic, so empty slots are drawn as real zeros. */
function fillGaps(overview: Overview, nowMs: number) {
  const bucketMs = overview.bucket_seconds * 1000
  const end = Math.floor(nowMs / bucketMs) * bucketMs
  const start = end - (WINDOW_SECONDS[overview.window] * 1000 - bucketMs)
  const known = new Map(overview.series.map((point) => [new Date(point.t).getTime(), point]))
  const points = []
  for (let time = start; time <= end; time += bucketMs) {
    const point = known.get(time)
    points.push({
      time,
      allowed: point?.allowed ?? 0,
      blocked: point?.blocked ?? 0,
      anomalies: point?.anomalies ?? 0,
    })
  }
  return points
}

export function TrafficChart({ overview, now }: { overview: Overview; now: Date }) {
  const points = React.useMemo(() => fillGaps(overview, now.getTime()), [overview, now])
  const short = overview.window === "7d"
  const format = React.useCallback(
    (value: number) =>
      new Date(value).toLocaleString(undefined, short ? { month: "short", day: "numeric", hour: "2-digit" } : { hour: "2-digit", minute: "2-digit" }),
    [short],
  )

  return (
    <ChartContainer config={config} className="aspect-auto h-72 w-full">
      <LineChart data={points} margin={{ left: 0, right: 12, top: 8 }}>
        <CartesianGrid vertical={false} stroke="var(--series-grid)" />
        <XAxis dataKey="time" tickLine={false} axisLine={false} tickMargin={8} minTickGap={48} tickFormatter={format} />
        <YAxis width={40} allowDecimals={false} tickLine={false} axisLine={false} />
        <ChartTooltip
          cursor={{ stroke: "var(--muted-foreground)" }}
          content={<ChartTooltipContent indicator="line" labelFormatter={(_, payload) => format(payload?.[0]?.payload?.time)} />}
        />
        <ChartLegend content={<ChartLegendContent />} />
        <Line dataKey="allowed" type="monotone" stroke="var(--color-allowed)" strokeWidth={2} dot={false} isAnimationActive={false} />
        <Line dataKey="blocked" type="monotone" stroke="var(--color-blocked)" strokeWidth={2} dot={false} isAnimationActive={false} />
        <Line dataKey="anomalies" type="monotone" stroke="var(--color-anomalies)" strokeWidth={2} dot={false} isAnimationActive={false} />
      </LineChart>
    </ChartContainer>
  )
}
