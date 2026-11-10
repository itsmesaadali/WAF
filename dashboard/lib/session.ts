import "server-only"

import { cookies } from "next/headers"

export const SESSION_COOKIE = "waf_session"

export function wafApiUrl(): string {
  const url = process.env.WAF_API_URL
  if (!url) throw new Error("WAF_API_URL is not configured")
  return `${url.replace(/\/$/, "")}/__waf/api`
}

export async function getSessionToken(): Promise<string | undefined> {
  return (await cookies()).get(SESSION_COOKIE)?.value
}

/** The login token stays in an httpOnly cookie, so browser JavaScript can never read it. */
export async function setSessionCookie(token: string, maxAgeSeconds: number): Promise<void> {
  ;(await cookies()).set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: maxAgeSeconds,
  })
}

export async function clearSessionCookie(): Promise<void> {
  ;(await cookies()).delete(SESSION_COOKIE)
}
