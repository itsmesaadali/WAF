"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import {
  ActivityIcon,
  BrainCircuitIcon,
  ClipboardListIcon,
  FlaskConicalIcon,
  HeartPulseIcon,
  LayoutDashboardIcon,
  Settings2Icon,
  ShieldAlertIcon,
  ShieldBanIcon,
  ShieldCheckIcon,
  SwordsIcon,
} from "lucide-react"

import { NavUser } from "@/components/nav-user"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar"

const GROUPS = [
  {
    label: "Monitoring",
    items: [
      { title: "Overview", url: "/dashboard", icon: LayoutDashboardIcon },
      { title: "Live traffic", url: "/traffic", icon: ActivityIcon },
      { title: "Incidents", url: "/incidents", icon: ShieldAlertIcon },
      { title: "ML anomalies", url: "/ml", icon: BrainCircuitIcon },
    ],
  },
  {
    label: "Management",
    items: [
      { title: "IP management", url: "/ips", icon: ShieldBanIcon },
      { title: "Attack lab", url: "/playground", icon: SwordsIcon },
      { title: "Attack simulator", url: "/simulator", icon: FlaskConicalIcon },
      { title: "Settings", url: "/settings", icon: Settings2Icon },
    ],
  },
  {
    label: "System",
    items: [
      { title: "System health", url: "/health", icon: HeartPulseIcon },
      { title: "Audit log", url: "/audit", icon: ClipboardListIcon },
    ],
  },
]

export function AppSidebar({ username, ...props }: React.ComponentProps<typeof Sidebar> & { username: string }) {
  const pathname = usePathname()
  const { setOpenMobile } = useSidebar()

  return (
    <Sidebar collapsible="offcanvas" {...props}>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton asChild className="data-[slot=sidebar-menu-button]:p-1.5!">
              <Link href="/dashboard" onClick={() => setOpenMobile(false)}>
                <ShieldCheckIcon className="size-5!" />
                <span className="text-base font-semibold">Hybrid WAF</span>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        {GROUPS.map((group) => (
          <SidebarGroup key={group.label}>
            <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {group.items.map((item) => (
                  <SidebarMenuItem key={item.url}>
                    <SidebarMenuButton asChild tooltip={item.title} isActive={pathname === item.url}>
                      <Link href={item.url} onClick={() => setOpenMobile(false)}>
                        <item.icon />
                        <span>{item.title}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}
      </SidebarContent>
      <SidebarFooter>
        <NavUser username={username} />
      </SidebarFooter>
    </Sidebar>
  )
}
