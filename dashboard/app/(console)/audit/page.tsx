"use client"

import { EmptyState, ErrorNotice, LastUpdated, LoadingRows } from "@/components/waf/shared"
import { Card, CardContent } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useLive } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import type { AuditEntry, Page } from "@/lib/types"

export default function AuditPage() {
  const { data, error, loading, updatedAt } = useLive<Page<AuditEntry>>("/audit?limit=100", 10000)

  return (
    <>
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-muted-foreground">Every sign-in and admin change, with who made it and when.</p>
        <LastUpdated at={updatedAt} />
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
                  <TableHead>Admin</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Details</TableHead>
                  <TableHead className="pr-4">IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((row) => {
                  const details = row.details ? JSON.stringify(row.details) : ""
                  return (
                    <TableRow key={row.id}>
                      <TableCell className="pl-4 whitespace-nowrap text-muted-foreground">{formatDateTime(row.created_at)}</TableCell>
                      <TableCell>{row.username}</TableCell>
                      <TableCell className="whitespace-nowrap">{row.action.replaceAll("_", " ")}</TableCell>
                      <TableCell className="font-mono text-xs">{row.target ?? "—"}</TableCell>
                      <TableCell className="max-w-80 truncate font-mono text-xs" title={details}>{details || "—"}</TableCell>
                      <TableCell className="pr-4 font-mono text-xs">{row.ip ?? "—"}</TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          ) : (
            <EmptyState title="No admin actions recorded" />
          )}
        </CardContent>
      </Card>
    </>
  )
}
