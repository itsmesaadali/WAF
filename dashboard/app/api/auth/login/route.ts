import { NextResponse, type NextRequest } from "next/server"

import { setSessionCookie, wafApiUrl } from "@/lib/session"
import { isSameOrigin } from "@/lib/same-origin"

export async function POST(request: NextRequest) {
  if (!isSameOrigin(request)) {
    return NextResponse.json({ detail: "Cross-site request refused" }, { status: 403 })
  }

  let upstream: Response
  try {
    upstream = await fetch(`${wafApiUrl()}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: await request.text(),
      cache: "no-store",
    })
  } catch {
    return NextResponse.json({ detail: "The WAF can't be reached" }, { status: 502 })
  }

  const body = await upstream.json().catch(() => ({ detail: "Unexpected WAF response" }))
  if (!upstream.ok) {
    return NextResponse.json({ detail: body.detail ?? "Login failed" }, { status: upstream.status })
  }
  await setSessionCookie(body.access_token, body.expires_in)
  return NextResponse.json({ username: body.username })
}
