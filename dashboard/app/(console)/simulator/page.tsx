"use client"

import * as React from "react"
import { PlayIcon } from "lucide-react"
import { toast } from "sonner"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { apiSend, useLive } from "@/lib/api"
import type { SimulationResult, WafSettings } from "@/lib/types"

const SCENARIOS = [
  { id: "normal", title: "Normal visitor", text: "Ordinary pages, a search and a form. These should all reach the website." },
  { id: "sqli", title: "SQL injection", text: "Tautologies, UNION queries and time-based injection in queries and forms." },
  { id: "xss", title: "Cross-site scripting", text: "Script tags, event handlers and script URLs." },
  { id: "evasion", title: "Evasion attempts", text: "Double encoding, SQL comments, HTML entities and base64 hiding." },
  { id: "anomaly", title: "ML anomaly", text: "Strange requests with no attack keywords. Only the ML layer should notice them." },
  { id: "rate_limit", title: "Rate limit burst", text: "More requests than the current per-minute limit, using one address." },
]

export default function SimulatorPage() {
  const settings = useLive<WafSettings>("/settings")
  const [running, setRunning] = React.useState<string | null>(null)
  const [result, setResult] = React.useState<SimulationResult | null>(null)
  const enabled = settings.data?.environment.simulator_enabled ?? true

  async function run(scenario: string) {
    setRunning(scenario)
    try {
      setResult(await apiSend<SimulationResult>("POST", "/simulator/run", { scenario }))
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Simulation failed")
    }
    setRunning(null)
  }

  return (
    <>
      <Alert>
        <AlertTitle>Fixed test requests, sent only to your configured website</AlertTitle>
        <AlertDescription>
          Target: {settings.data?.environment.upstream_url ?? "loading…"}. Requests pass through the real WAF from a reserved test address, and every record is marked as simulated. Requests the WAF allows do reach this website, so only use a site you&apos;re authorized to test.
        </AlertDescription>
      </Alert>

      <div className="grid gap-4 @3xl/main:grid-cols-2 @6xl/main:grid-cols-3">
        {SCENARIOS.map((scenario) => (
          <Card key={scenario.id}>
            <CardHeader>
              <CardTitle>{scenario.title}</CardTitle>
              <CardDescription>{scenario.text}</CardDescription>
            </CardHeader>
            <CardFooter className="mt-auto">
              <Button variant="outline" disabled={!enabled || running !== null} onClick={() => run(scenario.id)}>
                <PlayIcon />
                {running === scenario.id ? "Running…" : "Run"}
              </Button>
            </CardFooter>
          </Card>
        ))}
      </div>

      {result ? (
        <Card>
          <CardHeader>
            <CardTitle>Last run: {result.scenario.replace("_", " ")}</CardTitle>
            <CardDescription>
              {result.requests} requests from {result.simulated_ip}: {result.blocked} stopped by the WAF, {result.forwarded} forwarded. Results are also on the Traffic and Incidents pages.
            </CardDescription>
          </CardHeader>
          <CardContent className="px-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-4">Request</TableHead>
                  <TableHead className="pr-4 text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {result.results.map((row, index) => (
                  <TableRow key={index}>
                    <TableCell className="max-w-96 truncate pl-4 font-mono text-xs">{row.method} {row.path}</TableCell>
                    <TableCell className="pr-4 text-right tabular-nums">{row.status}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ) : null}
    </>
  )
}
