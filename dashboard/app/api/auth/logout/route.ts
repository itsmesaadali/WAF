import { NextResponse, type NextRequest } from "next/server"

import { isSameOrigin } from "@/lib/same-origin"
import { clearSessionCookie, getSessionToken, wafApiUrl } from "@/lib/session"

export async function POST(request: NextRequest) {
  if (!isSameOrigin(request)) {
    return NextResponse.json({ detail: "Cross-site request refused" }, { status: 403 })
  }
  const token = await getSessionToken()
  if (token) {
    // The local cookie is removed even when the WAF can't be reached.
    await fetch(`${wafApiUrl()}/auth/logout`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}` },
      cache: "no-store",
    }).catch(() => undefined)
  }
  await clearSessionCookie()
  return NextResponse.json({ ok: true })
}
