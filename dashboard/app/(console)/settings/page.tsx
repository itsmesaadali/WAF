"use client"

import * as React from "react"
import { toast } from "sonner"

import { ErrorNotice, LoadingRows } from "@/components/waf/shared"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { apiSend, useLive } from "@/lib/api"
import type { WafConfig, WafSettings } from "@/lib/types"

function ToggleRow({ id, title, text, checked, onChange }: { id: string; title: string; text: string; checked: boolean; onChange: (value: boolean) => void }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="flex flex-col gap-1">
        <Label htmlFor={id}>{title}</Label>
        <p className="text-sm text-muted-foreground">{text}</p>
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} />
    </div>
  )
}

function NumberField({ id, label, value, onChange, min, max }: { id: string; label: string; value: number; onChange: (value: number) => void; min: number; max: number }) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} type="number" min={min} max={max} required value={Number.isNaN(value) ? "" : value} onChange={(e) => onChange(e.target.valueAsNumber)} />
    </div>
  )
}

function ChangePassword() {
  const [current, setCurrent] = React.useState("")
  const [next, setNext] = React.useState("")
  const [busy, setBusy] = React.useState(false)

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true)
    try {
      await apiSend("POST", "/auth/change-password", { current_password: current, new_password: next })
      toast.success("Password changed. Please sign in again.")
      window.location.assign("/login")
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Password change failed")
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Change password</CardTitle>
        <CardDescription>Use at least 12 characters. All existing sessions sign out.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="grid max-w-md gap-4">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="current-password">Current password</Label>
            <Input id="current-password" type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="new-password">New password</Label>
            <Input id="new-password" type="password" autoComplete="new-password" required minLength={12} value={next} onChange={(e) => setNext(e.target.value)} />
          </div>
          <Button type="submit" variant="outline" className="justify-self-start" disabled={busy}>
            Change password
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}

function ProtectionForm({ initial, onSaved }: { initial: WafConfig; onSaved: () => void }) {
  const [draft, setDraft] = React.useState(initial)
  const [allowlist, setAllowlist] = React.useState(initial.ip_allowlist.join("\n"))
  const [busy, setBusy] = React.useState(false)

  function update<K extends keyof WafConfig>(key: K, value: WafConfig[K]) {
    setDraft((current) => ({ ...current, [key]: value }))
  }

  async function save(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true)
    try {
      const saved = await apiSend<WafConfig>("PATCH", "/settings", {
        ...draft,
        ip_allowlist: allowlist.split(/\s+/).filter(Boolean),
      })
      setDraft(saved)
      setAllowlist(saved.ip_allowlist.join("\n"))
      onSaved()
      toast.success("Settings saved and applied")
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Save failed")
    }
    setBusy(false)
  }

  return (
        <form onSubmit={save} className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Protection mode</CardTitle>
              <CardDescription>
                Block stops attacks. Monitor records what would have happened and lets the traffic through, so you can check for false positives. Monitor mode doesn&apos;t protect the website.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs value={draft.mode} onValueChange={(value) => update("mode", value as WafConfig["mode"])}>
                <TabsList>
                  <TabsTrigger value="block">Block</TabsTrigger>
                  <TabsTrigger value="monitor">Monitor</TabsTrigger>
                </TabsList>
              </Tabs>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Rate limits and bans</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4 @3xl/main:grid-cols-3">
              <NumberField id="rate" label="Requests per minute, per IP" min={5} max={100000} value={draft.rate_limit_per_minute} onChange={(v) => update("rate_limit_per_minute", v)} />
              <NumberField id="strikes" label="Blocked requests before a ban" min={1} max={1000} value={draft.strikes_before_ban} onChange={(v) => update("strikes_before_ban", v)} />
              <NumberField id="ban" label="Ban length in minutes" min={1} max={10080} value={draft.ban_minutes} onChange={(v) => update("ban_minutes", v)} />
              <div className="flex flex-col gap-1.5 @3xl/main:col-span-3">
                <Label htmlFor="allowlist">Allowlisted IPs or networks, one per line</Label>
                <Textarea id="allowlist" className="font-mono text-xs" value={allowlist} onChange={(e) => setAllowlist(e.target.value)} />
                <p className="text-xs text-muted-foreground">These skip bans and rate limits. Attack signatures still apply.</p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Machine learning</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4">
              <ToggleRow id="ml-enabled" title="Score requests with ML" text="Adds an anomaly score to every request." checked={draft.ml_enabled} onChange={(v) => update("ml_enabled", v)} />
              <ToggleRow id="ml-block" title="Block flagged requests" text="Off by default, because ML is supporting evidence and can flag legitimate traffic." checked={draft.ml_block} onChange={(v) => update("ml_block", v)} />
            </CardContent>
          </Card>

          <div>
            <Button type="submit" disabled={busy}>
              {busy ? "Saving…" : "Save settings"}
            </Button>
          </div>
        </form>
  )
}

export default function SettingsPage() {
  const { data, error, refresh } = useLive<WafSettings>("/settings")

  return (
    <>
      <ErrorNotice message={error} />
      {data ? <ProtectionForm initial={data.config} onSaved={refresh} /> : <LoadingRows rows={8} />}

      {data ? (
        <Card>
          <CardHeader>
            <CardTitle>Deployment configuration</CardTitle>
            <CardDescription>Read-only here. These values are set with environment variables on the WAF.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-2 text-sm @3xl/main:grid-cols-2">
            <p><span className="text-muted-foreground">Environment:</span> {data.environment.waf_env}</p>
            <p className="break-all"><span className="text-muted-foreground">Website:</span> {data.environment.upstream_url}</p>
            <p><span className="text-muted-foreground">If inspection fails:</span> fail {data.environment.fail_mode}</p>
            <p><span className="text-muted-foreground">Trusted proxies:</span> {data.environment.trust_proxy_hops}</p>
            <p><span className="text-muted-foreground">Largest request body:</span> {Math.round(data.environment.max_body_bytes / 1024)} KB</p>
            <p><span className="text-muted-foreground">Log retention:</span> {data.environment.log_retention_days} days</p>
          </CardContent>
        </Card>
      ) : null}

      <ChangePassword />
    </>
  )
}
