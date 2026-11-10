"use client"

import {
  AlertOctagonIcon,
  AlertTriangleIcon,
  CheckCircle2Icon,
  CircleIcon,
  CircleSlashIcon,
  FlagIcon,
  GaugeIcon,
  InfoIcon,
  ShieldXIcon,
} from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"

export function ErrorNotice({ message }: { message: string | null }) {
  if (!message) return null
  return (
    <Alert variant="destructive">
      <AlertTriangleIcon />
      <AlertTitle>Couldn&apos;t refresh this data</AlertTitle>
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  )
}

export function EmptyState({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-1 px-4 py-10 text-center">
      <InfoIcon className="mb-1 size-5 text-muted-foreground" aria-hidden />
      <p className="text-sm font-medium">{title}</p>
      {children ? <p className="max-w-md text-sm text-muted-foreground">{children}</p> : null}
    </div>
  )
}

export function LoadingRows({ rows = 5 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-2 p-4" aria-label="Loading">
      {Array.from({ length: rows }).map((_, index) => (
        <Skeleton key={index} className="h-8 w-full" />
      ))}
    </div>
  )
}

/** Status never relies on color alone: every badge also has an icon and a text label. */
const SEVERITY = {
  critical: { icon: AlertOctagonIcon, color: "var(--status-critical)", label: "Critical" },
  high: { icon: AlertTriangleIcon, color: "var(--status-serious)", label: "High" },
  medium: { icon: AlertTriangleIcon, color: "var(--status-warning)", label: "Medium" },
  low: { icon: CircleIcon, color: "var(--muted-foreground)", label: "Low" },
} as const

export function SeverityBadge({ severity }: { severity: string }) {
  const item = SEVERITY[severity as keyof typeof SEVERITY] ?? SEVERITY.low
  return (
    <Badge variant="outline" className="gap-1">
      <item.icon style={{ color: item.color }} aria-hidden />
      {item.label}
    </Badge>
  )
}

const ACTIONS = {
  allowed: { icon: CheckCircle2Icon, color: "var(--status-good)", label: "Allowed" },
  flagged: { icon: FlagIcon, color: "var(--status-warning)", label: "Flagged" },
  logged: { icon: FlagIcon, color: "var(--status-warning)", label: "Logged" },
  blocked: { icon: ShieldXIcon, color: "var(--status-critical)", label: "Blocked" },
  rate_limited: { icon: GaugeIcon, color: "var(--status-serious)", label: "Rate limited" },
  banned: { icon: CircleSlashIcon, color: "var(--status-critical)", label: "Banned" },
  error: { icon: AlertTriangleIcon, color: "var(--status-serious)", label: "Error" },
} as const

export function ActionBadge({ action }: { action: string }) {
  const item = ACTIONS[action as keyof typeof ACTIONS] ?? { icon: CircleIcon, color: "var(--muted-foreground)", label: action }
  return (
    <Badge variant="outline" className="gap-1">
      <item.icon style={{ color: item.color }} aria-hidden />
      {item.label}
    </Badge>
  )
}

export function SimulatedTag({ simulated }: { simulated: boolean }) {
  return simulated ? <Badge variant="secondary">Simulated</Badge> : null
}

export function LastUpdated({ at }: { at: Date | null }) {
  return (
    <span className="text-xs text-muted-foreground" aria-live="off">
      {at ? `Updated ${at.toLocaleTimeString()}` : "Connecting…"}
    </span>
  )
}

export function HealthBadge({ ok, good = "Healthy", bad = "Problem" }: { ok: boolean; good?: string; bad?: string }) {
  const Icon = ok ? CheckCircle2Icon : AlertOctagonIcon
  return (
    <Badge variant="outline" className="gap-1">
      <Icon style={{ color: ok ? "var(--status-good)" : "var(--status-critical)" }} aria-hidden />
      {ok ? good : bad}
    </Badge>
  )
}
