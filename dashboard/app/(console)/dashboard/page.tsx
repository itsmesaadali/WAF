"use client"

import * as React from "react"
import Link from "next/link"
import { Bar, BarChart, LabelList, XAxis, YAxis } from "recharts"

import { TrafficChart } from "@/components/waf/traffic-chart"
import { ActionBadge, EmptyState, ErrorNotice, LastUpdated, LoadingRows, SeverityBadge, SimulatedTag } from "@/components/waf/shared"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useLive } from "@/lib/api"
import { attackLabel, formatDateTime, formatMs, formatNumber } from "@/lib/format"
import type { Overview } from "@/lib/types"

const WINDOWS = [
  { value: "1h", label: "1 hour" },
  { value: "24h", label: "24 hours" },
  { value: "7d", label: "7 days" },
]

const typeConfig = { count: { label: "Incidents", color: "var(--series-blocked)" } } satisfies ChartConfig

function Stat({ title, value, note }: { title: string; value: string | null; note: string }) {
  return (
    <Card size="sm">
      <CardHeader>
        <CardDescription>{title}</CardDescription>
        <CardTitle className="text-2xl font-semibold tabular-nums">{value ?? <Skeleton className="h-8 w-20" />}</CardTitle>
      </CardHeader>
      <CardContent className="text-xs text-muted-foreground">{note}</CardContent>
    </Card>
  )
}

export default function OverviewPage() {
  const [windowName, setWindowName] = React.useState("1h")
  const { data, error, updatedAt } = useLive<Overview>(`/stats/overview?window=${windowName}`, 5000)
  const totals = data?.totals
  const stopped = totals ? totals.blocked + totals.rate_limited + totals.banned : 0

  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Tabs value={windowName} onValueChange={setWindowName}>
          <TabsList>
            {WINDOWS.map((item) => (
              <TabsTrigger key={item.value} value={item.value}>
                {item.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
        <LastUpdated at={updatedAt} />
      </div>

      <ErrorNotice message={error} />

      <div className="grid grid-cols-2 gap-4 @3xl/main:grid-cols-3 @6xl/main:grid-cols-6">
        <Stat title="Requests" value={totals ? formatNumber(totals.requests) : null} note={totals ? `${formatNumber(totals.unique_ips)} unique IPs` : "Loading"} />
        <Stat title="Stopped" value={totals ? formatNumber(stopped) : null} note={totals ? `${formatNumber(totals.rate_limited)} by rate limit` : "Loading"} />
        <Stat title="Incidents" value={totals ? formatNumber(totals.incidents) : null} note="Security events recorded" />
        <Stat title="ML anomalies" value={totals ? formatNumber(totals.anomalies) : null} note="Unusual requests flagged" />
        <Stat title="Active bans" value={data ? formatNumber(data.active_bans) : null} note="Temporary and manual" />
        <Stat title="WAF time (p95)" value={data ? formatMs(data.latency.waf_p95_ms) : null} note={data ? `Median ${formatMs(data.latency.waf_p50_ms)}` : "Loading"} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Traffic over time</CardTitle>
          <CardDescription>Requests the WAF forwarded or stopped, from the request log</CardDescription>
        </CardHeader>
        <CardContent>
          {!data || !updatedAt ? (
            <Skeleton className="h-72 w-full" />
          ) : totals?.requests ? (
            <TrafficChart overview={data} now={updatedAt} />
          ) : (
            <EmptyState title="No traffic in this period">Send requests through the WAF, or run the attack simulator.</EmptyState>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-4 @5xl/main:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Incidents by type</CardTitle>
            <CardDescription>Number of incidents in this period</CardDescription>
          </CardHeader>
          <CardContent>
            {!data ? (
              <LoadingRows rows={3} />
            ) : data.incidents_by_type.length ? (
              <ChartContainer config={typeConfig} className="aspect-auto w-full" style={{ height: Math.max(120, data.incidents_by_type.length * 44) }}>
                <BarChart data={data.incidents_by_type.map((row) => ({ ...row, label: attackLabel(row.type) }))} layout="vertical" margin={{ left: 8, right: 32 }}>
                  <YAxis dataKey="label" type="category" tickLine={false} axisLine={false} width={130} />
                  <XAxis type="number" hide allowDecimals={false} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent hideIndicator />} />
                  <Bar dataKey="count" fill="var(--color-count)" barSize={16} radius={[0, 4, 4, 0]} isAnimationActive={false}>
                    <LabelList dataKey="count" position="right" className="fill-foreground" fontSize={12} />
                  </Bar>
                </BarChart>
              </ChartContainer>
            ) : (
              <EmptyState title="No incidents in this period" />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top sources</CardTitle>
            <CardDescription>IP addresses with the most incidents in this period</CardDescription>
          </CardHeader>
          <CardContent className="px-0">
            {!data ? (
              <LoadingRows rows={3} />
            ) : data.top_ips.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="pl-4">IP address</TableHead>
                    <TableHead className="pr-4 text-right">Incidents</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.top_ips.map((row) => (
                    <TableRow key={row.ip}>
                      <TableCell className="pl-4 font-mono text-xs">
                        <Link className="underline-offset-2 hover:underline" href={`/incidents?ip=${encodeURIComponent(row.ip)}`}>
                          {row.ip}
                        </Link>
                      </TableCell>
                      <TableCell className="pr-4 text-right tabular-nums">{formatNumber(row.count)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <EmptyState title="No sources to show" />
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <div className="flex flex-col gap-1">
            <CardTitle>Latest incidents</CardTitle>
            <CardDescription>Most recent security events</CardDescription>
          </div>
          <Button asChild variant="outline" size="sm">
            <Link href="/incidents">View all</Link>
          </Button>
        </CardHeader>
        <CardContent className="px-0">
          {!data ? (
            <LoadingRows />
          ) : data.recent_incidents.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-4">Time</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Path</TableHead>
                  <TableHead className="pr-4">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.recent_incidents.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell className="pl-4 whitespace-nowrap text-muted-foreground">{formatDateTime(row.created_at)}</TableCell>
                    <TableCell className="whitespace-nowrap">
                      {attackLabel(row.attack_type)} <SimulatedTag simulated={row.simulated} />
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={row.severity} />
                    </TableCell>
                    <TableCell className="font-mono text-xs">{row.client_ip}</TableCell>
                    <TableCell className="max-w-48 truncate font-mono text-xs" title={row.path}>
                      {row.path}
                    </TableCell>
                    <TableCell className="pr-4">
                      <ActionBadge action={row.action_taken} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <EmptyState title="No incidents recorded yet">Blocked attacks and ML flags appear here as they happen.</EmptyState>
          )}
        </CardContent>
      </Card>
    </>
  )
}
