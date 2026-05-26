import * as React from "react"

import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"

interface DataStateProps {
  /** Loading: render `loading` slot instead of children. */
  isLoading?: boolean
  /** Error: render `errorFallback` instead of children. */
  isError?: boolean
  /** The raw error object — its `.message` is used in the default error slot. */
  error?: unknown
  /** Empty: render `empty` slot instead of children. */
  isEmpty?: boolean

  /** Override the loading slot. Defaults to N skeleton rows. */
  loading?: React.ReactNode
  /** Override the error slot. Defaults to a destructive-coloured message. */
  errorFallback?: React.ReactNode
  /** Override the empty slot. Defaults to centred icon + title + optional description. */
  empty?: React.ReactNode

  /** Convenience: icon for the default empty slot. */
  emptyIcon?: React.ComponentType<{ className?: string }>
  /** Convenience: heading for the default empty slot. */
  emptyTitle?: string
  /** Convenience: description for the default empty slot. */
  emptyDescription?: string

  /** Convenience: skeleton row count for the default loading slot. */
  skeletonRows?: number
  /** Convenience: skeleton row height utility. */
  skeletonHeight?: string

  className?: string
  children: React.ReactNode
}

function defaultErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message
  if (typeof err === "string") return err
  return "Something went wrong while loading this data."
}

/**
 * DataState collapses the four common render branches of a query-backed
 * surface — loading / error / empty / data — into one component.
 *
 * Pass the three boolean states from a TanStack Query (or any source)
 * and either let the defaults handle the chrome (skeleton rows,
 * destructive-coloured error, muted empty pane) or pass slot overrides
 * for a custom look. Children only render once all three booleans are
 * falsy — i.e. the data is ready.
 *
 * Why a single component instead of helpers: it's *much* harder to
 * accidentally forget the error or empty case when the parent has to
 * supply each branch up-front.
 */
function DataState({
  isLoading,
  isError,
  error,
  isEmpty,
  loading,
  errorFallback,
  empty,
  emptyIcon: EmptyIcon,
  emptyTitle,
  emptyDescription,
  skeletonRows = 6,
  skeletonHeight = "h-10",
  className,
  children,
}: DataStateProps) {
  if (isLoading) {
    return (
      <div data-slot="data-state" data-state="loading" className={cn("space-y-3 p-4", className)}>
        {loading ?? (
          <>
            {Array.from({ length: skeletonRows }, (_, i) => (
              <Skeleton key={i} className={cn(skeletonHeight, "w-full")} />
            ))}
          </>
        )}
      </div>
    )
  }

  if (isError) {
    return (
      <div
        data-slot="data-state"
        data-state="error"
        role="alert"
        className={cn("p-6 text-sm text-destructive", className)}
      >
        {errorFallback ?? defaultErrorMessage(error)}
      </div>
    )
  }

  if (isEmpty) {
    return (
      <div
        data-slot="data-state"
        data-state="empty"
        className={cn("flex flex-col items-center gap-2 p-10 text-center", className)}
      >
        {empty ?? (
          <>
            {EmptyIcon && <EmptyIcon className="size-8 text-muted-foreground" />}
            {emptyTitle && (
              <p className="text-sm font-medium text-foreground">{emptyTitle}</p>
            )}
            {emptyDescription && (
              <p className="text-xs text-muted-foreground">{emptyDescription}</p>
            )}
          </>
        )}
      </div>
    )
  }

  return <>{children}</>
}

export { DataState }
export type { DataStateProps }
