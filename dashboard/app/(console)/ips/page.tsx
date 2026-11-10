"use client"

import * as React from "react"
import { ShieldBanIcon } from "lucide-react"
import { toast } from "sonner"

import { EmptyState, ErrorNotice, LastUpdated, LoadingRows, SimulatedTag } from "@/components/waf/shared"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { apiSend, useLive } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import type { Ban } from "@/lib/types"

export default function IpManagementPage() {
  const [showHistory, setShowHistory] = React.useState(false)
  const { data, error, loading, updatedAt, refresh } = useLive<{ items: Ban[] }>(`/bans?active_only=${!showHistory}&limit=200`, 5000)
  const [ip, setIp] = React.useState("")
  const [reason, setReason] = React.useState("")
  const [minutes, setMinutes] = React.useState("60")
  const [busy, setBusy] = React.useState(false)
  const [confirming, setConfirming] = React.useState<Ban | null>(null)

  async function addBan(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true)
    try {
      await apiSend("POST", "/bans", { ip, reason, minutes: minutes ? Number(minutes) : null })
      toast.success(`${ip} is banned`)
      setIp("")
      setReason("")
      refresh()
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Ban failed")
    }
    setBusy(false)
  }

  async function liftBan() {
    if (!confirming) return
    setBusy(true)
    try {
      await apiSend("DELETE", `/bans/${confirming.id}`)
      toast.success(`${confirming.ip} is no longer banned`)
      refresh()
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Unban failed")
    }
    setConfirming(null)
    setBusy(false)
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Ban an IP address</CardTitle>
          <CardDescription>Leave the minutes empty to ban until an admin lifts it. Banned visitors get a 403 page.</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={addBan} className="flex flex-wrap items-end gap-3">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="ban-ip">IP address</Label>
              <Input id="ban-ip" required className="w-48" placeholder="192.0.2.10" value={ip} onChange={(e) => setIp(e.target.value)} />
            </div>
            <div className="flex min-w-56 flex-1 flex-col gap-1.5">
              <Label htmlFor="ban-reason">Reason</Label>
              <Input id="ban-reason" required minLength={3} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="ban-minutes">Minutes</Label>
              <Input id="ban-minutes" className="w-24" type="number" min={1} max={525600} value={minutes} onChange={(e) => setMinutes(e.target.value)} />
            </div>
            <Button type="submit" disabled={busy}>
              <ShieldBanIcon />
              Ban IP
            </Button>
          </form>
        </CardContent>
      </Card>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Switch id="ban-history" checked={showHistory} onCheckedChange={setShowHistory} />
          <Label htmlFor="ban-history">Include past bans</Label>
        </div>
        <LastUpdated at={updatedAt} />
      </div>

      <ErrorNotice message={error} />

      <Card className="py-0">
        <CardContent className="px-0">
          {loading && !data ? (
            <LoadingRows />
          ) : data?.items.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-4">IP address</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Banned at</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead className="pr-4 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell className="pl-4 whitespace-nowrap font-mono text-xs">
                      {row.ip} <SimulatedTag simulated={row.simulated} />
                    </TableCell>
                    <TableCell className="max-w-64 truncate" title={row.reason}>{row.reason}</TableCell>
                    <TableCell>{row.source === "auto" ? "Automatic" : `Manual (${row.created_by})`}</TableCell>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(row.created_at)}</TableCell>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{row.expires_at ? formatDateTime(row.expires_at) : "Never"}</TableCell>
                    <TableCell>
                      <Badge variant={row.active ? "default" : "outline"}>{row.active ? "Active" : row.lifted_at ? "Lifted" : "Expired"}</Badge>
                    </TableCell>
                    <TableCell className="pr-4 text-right">
                      {row.active ? (
                        <Button variant="outline" size="sm" onClick={() => setConfirming(row)}>
                          Unban
                        </Button>
                      ) : null}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <EmptyState title={showHistory ? "No bans recorded" : "No active bans"}>
              IPs are banned automatically after repeated attacks, or manually from the form above.
            </EmptyState>
          )}
        </CardContent>
      </Card>

      <Dialog open={confirming !== null} onOpenChange={(open) => !open && setConfirming(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Unban {confirming?.ip}?</DialogTitle>
            <DialogDescription>This IP can send requests again straight away. The action is recorded in the audit log.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirming(null)}>Cancel</Button>
            <Button disabled={busy} onClick={liftBan}>Unban</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
