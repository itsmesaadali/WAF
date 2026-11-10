"use client"

import * as React from "react"

const BASE = "/api/waf"

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message)
  }
}

function describe(body: unknown, status: number): string {
  const detail = (body as { detail?: unknown } | null)?.detail
  if (typeof detail === "string") return detail
  return `Request failed with status ${status}`
}

async function handle<T>(response: Response): Promise<T> {
  if (response.status === 401) {
    window.location.assign("/login")
    throw new ApiError("Your session has ended", 401)
  }
  const body = await response.json().catch(() => null)
  if (!response.ok) throw new ApiError(describe(body, response.status), response.status)
  return body as T
}

export async function apiSend<T>(method: "POST" | "PATCH" | "DELETE", path: string, body?: unknown): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  return handle<T>(response)
}

export type LiveData<T> = {
  data: T | null
  error: string | null
  loading: boolean
  refresh: () => void
  updatedAt: Date | null
}

/**
 * Reads real data from the WAF, and repeats on an interval. Polling pauses while the tab is
 * hidden, and old data stays on screen with an error message if a refresh fails.
 */
export function useLive<T>(path: string | null, refreshMs = 0): LiveData<T> {
  const [state, setState] = React.useState<{
    data: T | null
    error: string | null
    updatedAt: Date | null
    loadedPath: string | null
  }>({ data: null, error: null, updatedAt: null, loadedPath: null })
  const [refreshCount, setRefreshCount] = React.useState(0)

  React.useEffect(() => {
    if (!path) return
    let active = true
    let inFlight = false

    async function load() {
      if (inFlight) return
      inFlight = true
      try {
        const response = await fetch(`${BASE}${path}`, { cache: "no-store" })
        const body = await handle<T>(response)
        if (active) setState({ data: body, error: null, updatedAt: new Date(), loadedPath: path })
      } catch (cause) {
        if (active) {
          const message = cause instanceof Error ? cause.message : "The request failed"
          setState((current) => ({ ...current, error: message, loadedPath: path }))
        }
      } finally {
        inFlight = false
      }
    }

    void load()
    const timer = refreshMs
      ? setInterval(() => {
          if (document.visibilityState === "visible") void load()
        }, refreshMs)
      : undefined
    return () => {
      active = false
      if (timer) clearInterval(timer)
    }
  }, [path, refreshMs, refreshCount])

  const refresh = React.useCallback(() => setRefreshCount((count) => count + 1), [])
  return {
    data: state.data,
    error: state.error,
    loading: state.loadedPath !== path,
    refresh,
    updatedAt: state.updatedAt,
  }
}
