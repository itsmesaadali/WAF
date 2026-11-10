"use client"

import * as React from "react"
import { PauseIcon, PlayIcon } from "lucide-react"

import { ActionBadge, EmptyState, ErrorNotice, LastUpdated, LoadingRows, SimulatedTag } from "@/components/waf/shared"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useLive } from "@/lib/api"
import { formatDateTime, formatMs } from "@/lib/format"
import type { Page, RequestRow } from "@/lib/types"

const ACTIONS = ["allowed", "flagged", "blocked", "rate_limited", "banned", "error"]
const ALL = "all"

export default function TrafficPage() {
  const [action, setAction] = React.useState(ALL)
  const [search, setSearch] = React.useState("")
  const [hideSimulated, setHideSimulated] = React.useState(false)
  const [paused, setPaused] = React.useState(false)

  const params = new URLSearchParams({ limit: "100" })
  if (action !== ALL) params.set("action", action)
  if (search.trim()) params.set("search", search.trim())
  if (hideSimulated) params.set("hide_simulated", "true")

  const { data, error, loading, updatedAt } = useLive<Page<RequestRow>>(`/traffic?${params}`, paused ? 0 : 3000)

  return (
    <>
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="traffic-search">Search path</Label>
          <Input id="traffic-search" className="w-56" placeholder="/products" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label>Result</Label>
          <Select value={action} onValueChange={setAction}>
            <SelectTrigger className="w-40" aria-label="Filter by result">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>All results</SelectItem>
              {ACTIONS.map((item) => (
                <SelectItem key={item} value={item}>
                  {item.replace("_", " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex h-8 items-center gap-2">
          <Switch id="hide-simulated" checked={hideSimulated} onCheckedChange={setHideSimulated} />
          <Label htmlFor="hide-simulated">Hide simulated</Label>
        </div>
        <div className="ml-auto flex items-center gap-3">
          <LastUpdated at={updatedAt} />
          <Button variant="outline" size="sm" onClick={() => setPaused((value) => !value)}>
            {paused ? <PlayIcon /> : <PauseIcon />}
            {paused ? "Resume" : "Pause"}
          </Button>
        </div>
      </div>

      <ErrorNotice message={error} />

      <Card className="py-0">
        <CardContent className="px-0">
          {loading && !data ? (
            <LoadingRows rows={8} />
          ) : data?.items.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-4">Time</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Request</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Result</TableHead>
                  <TableHead className="text-right">WAF</TableHead>
                  <TableHead className="text-right">Website</TableHead>
                  <TableHead className="pr-4 text-right">ML score</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell className="pl-4 whitespace-nowrap text-muted-foreground">{formatDateTime(row.created_at)}</TableCell>
                    <TableCell className="whitespace-nowrap font-mono text-xs">
                      {row.client_ip} <SimulatedTag simulated={row.simulated} />
                    </TableCell>
                    <TableCell className="max-w-72 truncate font-mono text-xs" title={`${row.method} ${row.path}${row.query ? `?${row.query}` : ""}`}>
                      <span className="font-semibold">{row.method}</span> {row.path}
                      {row.query ? <span className="text-muted-foreground">?{row.query}</span> : null}
                    </TableCell>
                    <TableCell className="tabular-nums">{row.status_code}</TableCell>
                    <TableCell>
                      <ActionBadge action={row.action} />
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{formatMs(row.waf_ms)}</TableCell>
                    <TableCell className="text-right tabular-nums">{formatMs(row.upstream_ms)}</TableCell>
                    <TableCell className="pr-4 text-right tabular-nums">
                      {row.is_anomaly ? <Badge variant="outline">{row.anomaly_score?.toFixed(3)}</Badge> : (row.anomaly_score?.toFixed(3) ?? "—")}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <EmptyState title="No matching traffic">Requests appear here within a few seconds of passing through the WAF.</EmptyState>
          )}
        </CardContent>
      </Card>
    </>
  )
}
