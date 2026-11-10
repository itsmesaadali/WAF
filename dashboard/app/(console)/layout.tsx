import { redirect } from "next/navigation"

import { AppSidebar } from "@/components/app-sidebar"
import { SiteHeader } from "@/components/site-header"
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"
import { getSessionToken, wafApiUrl } from "@/lib/session"

type SessionCheck = { kind: "ok"; username: string } | { kind: "signed-out" } | { kind: "unreachable" }

async function checkSession(): Promise<SessionCheck> {
  const token = await getSessionToken()
  if (!token) return { kind: "signed-out" }
  try {
    const response = await fetch(`${wafApiUrl()}/auth/me`, {
      headers: { authorization: `Bearer ${token}` },
      cache: "no-store",
    })
    if (response.status === 401) return { kind: "signed-out" }
    if (!response.ok) return { kind: "unreachable" }
    return { kind: "ok", username: (await response.json()).username }
  } catch {
    return { kind: "unreachable" }
  }
}

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const session = await checkSession()
  if (session.kind === "signed-out") redirect("/login")

  return (
    <SidebarProvider
      style={
        {
          "--sidebar-width": "calc(var(--spacing) * 64)",
          "--header-height": "calc(var(--spacing) * 12)",
        } as React.CSSProperties
      }
    >
      <AppSidebar variant="inset" username={session.kind === "ok" ? session.username : "unknown"} />
      <SidebarInset className="min-w-0">
        <SiteHeader />
        <div className="@container/main flex min-w-0 flex-1 flex-col gap-4 p-4 lg:gap-6 lg:p-6">
          {session.kind === "unreachable" ? (
            <p role="alert" className="border border-destructive/50 p-4 text-sm">
              The dashboard can&apos;t reach the WAF. Check that the WAF is running and that WAF_API_URL is correct.
            </p>
          ) : (
            children
          )}
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}
