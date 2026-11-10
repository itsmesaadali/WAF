import { NextResponse, type NextRequest } from "next/server"

import { isSameOrigin } from "@/lib/same-origin"
import { clearSessionCookie, getSessionToken, wafApiUrl } from "@/lib/session"

/**
 * Server-side bridge from the browser to the WAF's admin API.
 * It keeps the login token out of the browser, and means the WAF needs no CORS rules.
 */
type Context = { params: Promise<{ path: string[] }> }

const SAFE_SEGMENT = /^[A-Za-z0-9._-]+$/
const BLOCKED_PREFIXES = new Set(["auth/login", "auth/logout"])

async function forward(request: NextRequest, { params }: Context) {
  if (request.method !== "GET" && !isSameOrigin(request)) {
    return NextResponse.json({ detail: "Cross-site request refused" }, { status: 403 })
  }

  const { path } = await params
  const joined = path.join("/")
  if (!path.every((part) => SAFE_SEGMENT.test(part) && part !== "." && part !== "..") || BLOCKED_PREFIXES.has(joined)) {
    return NextResponse.json({ detail: "Not found" }, { status: 404 })
  }

  const token = await getSessionToken()
  if (!token) return NextResponse.json({ detail: "Not authenticated" }, { status: 401 })

  let upstream: Response
  try {
    upstream = await fetch(`${wafApiUrl()}/${joined}${request.nextUrl.search}`, {
      method: request.method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(request.method === "GET" ? {} : { "content-type": "application/json" }),
      },
      body: request.method === "GET" ? undefined : await request.text(),
      cache: "no-store",
    })
  } catch {
    return NextResponse.json({ detail: "The WAF can't be reached" }, { status: 502 })
  }

  if (upstream.status === 401) await clearSessionCookie()

  const headers = new Headers({ "cache-control": "no-store" })
  for (const name of ["content-type", "content-disposition"]) {
    const value = upstream.headers.get(name)
    if (value) headers.set(name, value)
  }
  return new NextResponse(upstream.body, { status: upstream.status, headers })
}

export const GET = forward
export const POST = forward
export const PATCH = forward
export const DELETE = forward
