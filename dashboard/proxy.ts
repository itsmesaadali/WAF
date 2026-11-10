import { NextResponse, type NextRequest } from "next/server"

/**
 * A quick check that sends signed-out visitors to the login page.
 * It only looks for the cookie: the console layout and the WAF verify the token itself.
 */
export function proxy(request: NextRequest) {
  if (!request.cookies.has("waf_session")) {
    return NextResponse.redirect(new URL("/login", request.url))
  }
  return NextResponse.next()
}

export const config = {
  matcher: ["/", "/dashboard", "/traffic", "/incidents", "/ips", "/ml", "/simulator", "/health", "/settings", "/audit"],
}
