"use client"

import * as React from "react"
import { useSearchParams } from "next/navigation"
import { DownloadIcon, ShieldBanIcon } from "lucide-react"
import { toast } from "sonner"

import { ActionBadge, EmptyState, ErrorNotice, LastUpdated, LoadingRows, SeverityBadge, SimulatedTag } from "@/components/waf/shared"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { apiSend, useLive } from "@/lib/api"
import { attackLabel, formatDateTime } from "@/lib/format"
import type { Incident, Page } from "@/lib/types"

const ALL = "all"
const TYPES = ["sqli", "xss", "evasion", "anomaly", "rate_limit", "banned_ip", "inspection_error"]
const SEVERITIES = ["critical", "high", "medium", "low"]
const STATUSES = [
  { value: "open", label: "Open" },
  { value: "reviewed", label: "Reviewed" },
  { value: "false_positive", label: "False positive" },
]

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  options: { value: string; label: string }[]
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label>{label}</Label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger className="w-44" aria-label={`Filter by ${label.toLowerCase()}`}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>All</SelectItem>
          {options.map((option) => (
            <SelectItem key={option.value} value={option.value}>
              {option.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}

function Detail({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="text-sm break-words">{children}</dd>
    </div>
  )
}

function IncidentsContent() {
  const initialIp = useSearchParams().get("ip") ?? ""
  const [type, setType] = React.useState(ALL)
  const [severity, setSeverity] = React.useState(ALL)
  const [status, setStatus] = React.useState(ALL)
  const [ip, setIp] = React.useState(initialIp)
  const [hideSimulated, setHideSimulated] = React.useState(false)
  const [selected, setSelected] = React.useState<Incident | null>(null)
  const [busy, setBusy] = React.useState(false)

  const params = new URLSearchParams()
  if (type !== ALL) params.set("attack_type", type)
  if (severity !== ALL) params.set("severity", severity)
  if (status !== ALL) params.set("status", status)
  if (ip.trim()) params.set("ip", ip.trim())
  if (hideSimulated) params.set("hide_simulated", "true")

  const { data, error, loading, updatedAt, refresh } = useLive<Page<Incident>>(`/incidents?limit=100&${params}`, 5000)

  async function setIncidentStatus(next: string) {
    if (!selected) return
    setBusy(true)
    try {
      setSelected(await apiSend<Incident>("PATCH", `/incidents/${selected.id}`, { status: next }))
      refresh()
      toast.success("Incident updated")
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Update failed")
    }
    setBusy(false)
  }

  async function banSource() {
    if (!selected) return
    setBusy(true)
    try {
      await apiSend("POST", "/bans", { ip: selected.client_ip, reason: `From incident ${selected.id}: ${attackLabel(selected.attack_type)}`, minutes: 60 })
      toast.success(`${selected.client_ip} is banned for 60 minutes`)
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Ban failed")
    }
    setBusy(false)
  }

  return (
    <>
      <div className="flex flex-wrap items-end gap-3">
        <FilterSelect label="Type" value={type} onChange={setType} options={TYPES.map((value) => ({ value, label: attackLabel(value) }))} />
        <FilterSelect label="Severity" value={severity} onChange={setSeverity} options={SEVERITIES.map((value) => ({ value, label: value[0].toUpperCase() + value.slice(1) }))} />
        <FilterSelect label="Status" value={status} onChange={setStatus} options={STATUSES} />
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="incident-ip">IP address</Label>
          <Input id="incident-ip" className="w-40" value={ip} onChange={(e) => setIp(e.target.value)} />
        </div>
        <div className="flex h-8 items-center gap-2">
          <Switch id="incident-simulated" checked={hideSimulated} onCheckedChange={setHideSimulated} />
          <Label htmlFor="incident-simulated">Hide simulated</Label>
        </div>
        <div className="ml-auto flex items-center gap-3">
          <LastUpdated at={updatedAt} />
          <Button asChild variant="outline" size="sm">
            <a href={`/api/waf/incidents/export.csv?${params}`} download>
              <DownloadIcon />
              Export CSV
            </a>
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
                  <TableHead>Type</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Rule</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Path</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead className="pr-4">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((row) => (
                  <TableRow
                    key={row.id}
                    tabIndex={0}
                    className="cursor-pointer"
                    onClick={() => setSelected(row)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") setSelected(row)
                    }}
                  >
                    <TableCell className="pl-4 whitespace-nowrap text-muted-foreground">{formatDateTime(row.created_at)}</TableCell>
                    <TableCell className="whitespace-nowrap">
                      {attackLabel(row.attack_type)} <SimulatedTag simulated={row.simulated} />
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={row.severity} />
                    </TableCell>
                    <TableCell className="font-mono text-xs">{row.rule_id ?? "—"}</TableCell>
                    <TableCell className="font-mono text-xs">{row.client_ip}</TableCell>
                    <TableCell className="max-w-44 truncate font-mono text-xs" title={row.path}>
                      {row.path}
                    </TableCell>
                    <TableCell>
                      <ActionBadge action={row.action_taken} />
                    </TableCell>
                    <TableCell className="pr-4 whitespace-nowrap">{row.status.replace("_", " ")}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <EmptyState title="No matching incidents">Incidents are saved permanently as attacks are detected.</EmptyState>
          )}
        </CardContent>
      </Card>

      <Sheet open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent className="overflow-y-auto">
          {selected ? (
            <>
              <SheetHeader>
                <SheetTitle>{attackLabel(selected.attack_type)}</SheetTitle>
                <SheetDescription>Incident {selected.id}</SheetDescription>
              </SheetHeader>
              <div className="flex flex-col gap-4 px-4 pb-4">
                <div className="flex flex-wrap gap-2">
                  <SeverityBadge severity={selected.severity} />
                  <ActionBadge action={selected.action_taken} />
                  <Badge variant="outline">{selected.mode} mode</Badge>
                  <SimulatedTag simulated={selected.simulated} />
                </div>
                <dl className="grid gap-3">
                  <Detail label="Time">{formatDateTime(selected.created_at)}</Detail>
                  <Detail label="Source IP"><span className="font-mono">{selected.client_ip}</span></Detail>
                  <Detail label="Request"><span className="font-mono">{selected.method} {selected.path}</span></Detail>
                  <Detail label="Rule">{selected.rule_id ? `${selected.rule_id}: ${selected.rule_name}` : "—"}</Detail>
                  <Detail label="Found in">{selected.location ?? "—"}</Detail>
                  <Detail label="ML anomaly score">{selected.anomaly_score?.toFixed(3) ?? "—"}</Detail>
                  <Detail label="Matched text (shown as plain text, secrets removed)">
                    {selected.evidence ? <code className="block bg-muted p-2 font-mono text-xs break-all">{selected.evidence}</code> : "—"}
                  </Detail>
                </dl>
                <div className="flex flex-col gap-1.5">
                  <Label>Review status</Label>
                  <Select value={selected.status} onValueChange={setIncidentStatus} disabled={busy}>
                    <SelectTrigger className="w-full" aria-label="Review status">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {STATUSES.map((option) => (
                        <SelectItem key={option.value} value={option.value}>
                          {option.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <Button variant="outline" disabled={busy} onClick={banSource}>
                  <ShieldBanIcon />
                  Ban this IP for 60 minutes
                </Button>
              </div>
            </>
          ) : null}
        </SheetContent>
      </Sheet>
    </>
  )
}

export default function IncidentsPage() {
  return (
    <React.Suspense fallback={<LoadingRows rows={8} />}>
      <IncidentsContent />
    </React.Suspense>
  )
}
