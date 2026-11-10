"use client"

import { usePathname } from "next/navigation"

import { ThemeToggle } from "@/components/waf/theme-toggle"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { SidebarTrigger } from "@/components/ui/sidebar"
import { useLive } from "@/lib/api"
import type { WafSettings } from "@/lib/types"

const TITLES: Record<string, string> = {
  "/dashboard": "Overview",
  "/traffic": "Live traffic",
  "/incidents": "Incidents",
  "/ml": "ML anomalies",
  "/ips": "IP management",
  "/playground": "Attack lab",
  "/simulator": "Attack simulator",
  "/settings": "Settings",
  "/health": "System health",
  "/audit": "Audit log",
}

export function SiteHeader() {
  const pathname = usePathname()
  const { data } = useLive<WafSettings>("/settings", 10000)
  let target = ""
  if (data) {
    try {
      target = new URL(data.environment.upstream_url).host
    } catch {
      target = data.environment.upstream_url
    }
  }

  return (
    <header className="flex h-(--header-height) shrink-0 items-center gap-2 border-b">
      <div className="flex w-full min-w-0 items-center gap-1 px-4 lg:gap-2 lg:px-6">
        <SidebarTrigger className="-ml-1" />
        <Separator orientation="vertical" className="mx-2 data-[orientation=vertical]:h-4" />
        <h1 className="truncate text-base font-medium">{TITLES[pathname] ?? "Hybrid WAF"}</h1>
        <div className="ml-auto flex items-center gap-2">
          {data ? (
            <>
              <span className="hidden truncate text-xs text-muted-foreground lg:inline" title="Website behind the WAF">
                Protecting {target}
              </span>
              <Badge variant="outline" className="hidden sm:inline-flex">
                {data.environment.waf_env.toUpperCase()}
              </Badge>
              <Badge variant={data.config.mode === "block" ? "default" : "secondary"}>
                {data.config.mode === "block" ? "Block mode" : "Monitor mode"}
              </Badge>
            </>
          ) : null}
          <ThemeToggle />
        </div>
      </div>
    </header>
  )
}
