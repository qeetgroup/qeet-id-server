import {
  Button,
  buttonVariants,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  StatusPill,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  cn,
} from "@qeetid/ui";
import { useMutation } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import {
  ArrowLeftIcon,
  FileUpIcon,
  Loader2Icon,
  UploadCloudIcon,
  XIcon,
} from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/users/import")({ component: ImportUsersPage });

// ---------------------------------------------------------------------------
// Parsers
//
// CSV is a tiny format here — header row + comma-separated values, double-
// quote escapes per RFC 4180. We don't need a heavyweight library for the
// shapes the bulk endpoint accepts (email/password/display_name/phone).
// NDJSON is one JSON object per line. Either way we end up with a homogeneous
// `Row[]` ready to POST.
// ---------------------------------------------------------------------------

interface Row {
  email: string
  password?: string
  display_name?: string
  phone?: string
  /** Raw line number from the source file, for error reporting. */
  _line: number
  /** Per-row validation error surfaced in the preview. */
  _error?: string
}

function parseCSVLine(line: string): string[] {
  const out: string[] = []
  let cur = ""
  let inQ = false
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (inQ) {
      if (c === '"' && line[i + 1] === '"') {
        cur += '"'
        i++
      } else if (c === '"') {
        inQ = false
      } else {
        cur += c
      }
    } else if (c === '"') {
      inQ = true
    } else if (c === ",") {
      out.push(cur)
      cur = ""
    } else {
      cur += c
    }
  }
  out.push(cur)
  return out.map((s) => s.trim())
}

function parseCSV(text: string): Row[] {
  const lines = text
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .filter((l) => l.trim() !== "")
  if (lines.length === 0) return []
  const header = parseCSVLine(lines[0]).map((h) => h.toLowerCase())
  return lines.slice(1).map((line, idx) => {
    const cols = parseCSVLine(line)
    const get = (key: string) => {
      const i = header.indexOf(key)
      return i >= 0 ? cols[i] ?? "" : ""
    }
    const row: Row = {
      email: get("email"),
      password: get("password") || undefined,
      display_name: get("display_name") || undefined,
      phone: get("phone") || undefined,
      _line: idx + 2, // +1 for 0-index, +1 for the header row
    }
    if (!row.email) row._error = "Missing email"
    return row
  })
}

function parseNDJSON(text: string): Row[] {
  return text
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .map((l) => l.trim())
    .map((line, idx) => {
      const lineNum = idx + 1
      if (!line) return null
      try {
        const obj = JSON.parse(line) as Record<string, unknown>
        const row: Row = {
          email: String(obj.email ?? ""),
          password: typeof obj.password === "string" ? obj.password : undefined,
          display_name:
            typeof obj.display_name === "string" ? obj.display_name : undefined,
          phone: typeof obj.phone === "string" ? obj.phone : undefined,
          _line: lineNum,
        }
        if (!row.email) row._error = "Missing email"
        return row
      } catch {
        return {
          email: "",
          _line: lineNum,
          _error: "Invalid JSON on this line",
        } satisfies Row
      }
    })
    .filter((r): r is Row => r !== null)
}

interface ImportResult {
  succeeded: number
  failed: number
  errors?: Array<{ line?: number; email?: string; message: string }>
}

function ImportUsersPage() {
  const tenantId = useTenantId()
  const [rows, setRows] = useState<Row[] | null>(null)
  const [fileName, setFileName] = useState<string | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const [result, setResult] = useState<ImportResult | null>(null)

  const importM = useMutation({
    mutationFn: async (toSubmit: Row[]): Promise<ImportResult> => {
      // Backend endpoint per GAP-ANALYSIS P1-10. Until it ships, surface a
      // friendly fallback instead of a generic 404.
      try {
        return await api<ImportResult>("/v1/users/bulk", {
          method: "POST",
          body: {
            tenant_id: tenantId,
            users: toSubmit.map(({ _line, _error, ...rest }) => {
              void _line
              void _error
              return rest
            }),
          },
        })
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) {
          throw new ApiError(
            404,
            "endpoint_unavailable",
            "Bulk import endpoint is not enabled on this instance yet (GAP-ANALYSIS P1-10).",
          )
        }
        throw err
      }
    },
    onSuccess: (res) => setResult(res),
    meta: { successMessage: "Bulk import queued" },
  })

  const validRows = rows?.filter((r) => !r._error) ?? []
  const invalidRows = rows?.filter((r) => !!r._error) ?? []

  async function handleFile(file: File) {
    setResult(null)
    setFileName(file.name)
    const text = await file.text()
    const lowerName = file.name.toLowerCase()
    const parsed =
      lowerName.endsWith(".ndjson") || lowerName.endsWith(".jsonl")
        ? parseNDJSON(text)
        : parseCSV(text)
    setRows(parsed)
  }

  function reset() {
    setRows(null)
    setFileName(null)
    setResult(null)
    importM.reset()
  }

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Bulk-import users from a CSV or newline-delimited JSON file. Email is required; password / display_name / phone are optional."
        actions={
          <Link to="/users" className={buttonVariants({ variant: "outline", size: "sm" })}>
            <ArrowLeftIcon /> Back to users
          </Link>
        }
      />

      {/* File picker */}
      {!rows && (
        <Card>
          <CardContent className="p-0">
            <label
              onDragOver={(e) => {
                e.preventDefault()
                setDragOver(true)
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault()
                setDragOver(false)
                const file = e.dataTransfer.files[0]
                if (file) handleFile(file)
              }}
              className={cn(
                "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed p-12 text-center transition-colors",
                dragOver ? "border-primary bg-primary/5" : "border-muted-foreground/30",
              )}
            >
              <UploadCloudIcon className="size-8 text-muted-foreground" />
              <p className="text-sm font-medium">Drop your CSV or NDJSON file</p>
              <p className="text-xs text-muted-foreground">
                or click anywhere in this box to browse
              </p>
              <input
                type="file"
                accept=".csv,.ndjson,.jsonl,text/csv,application/x-ndjson"
                className="sr-only"
                onChange={(e) => {
                  const f = e.target.files?.[0]
                  if (f) handleFile(f)
                }}
              />
            </label>
          </CardContent>
        </Card>
      )}

      {/* Preview */}
      {rows && !result && (
        <Card>
          <CardHeader className="flex flex-row items-start justify-between gap-3">
            <div>
              <CardTitle className="text-base">
                Preview <span className="text-muted-foreground">{fileName}</span>
              </CardTitle>
              <CardDescription>
                {validRows.length} valid row{validRows.length === 1 ? "" : "s"}
                {invalidRows.length > 0 && (
                  <span className="text-rose-600 dark:text-rose-400">
                    {" "}
                    · {invalidRows.length} skipped (validation errors)
                  </span>
                )}
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="ghost" size="sm" onClick={reset}>
                <XIcon /> Cancel
              </Button>
              <Button
                size="sm"
                disabled={validRows.length === 0 || importM.isPending}
                onClick={() => importM.mutate(validRows)}
              >
                {importM.isPending ? (
                  <Loader2Icon className="animate-spin" />
                ) : (
                  <FileUpIcon />
                )}
                Import {validRows.length} user{validRows.length === 1 ? "" : "s"}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            {importM.error && (
              <div className="border-b p-3 text-sm text-destructive">
                {(importM.error as Error).message}
              </div>
            )}
            <DataState
              isLoading={false}
              isEmpty={(rows?.length ?? 0) === 0}
              emptyTitle="No rows in the file."
            >
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-12">#</TableHead>
                    <TableHead>Email</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Phone</TableHead>
                    <TableHead>Password</TableHead>
                    <TableHead className="text-right">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows!.slice(0, 100).map((r, idx) => (
                    <TableRow key={idx}>
                      <TableCell className="text-muted-foreground">{r._line}</TableCell>
                      <TableCell className="font-mono text-xs">{r.email || "—"}</TableCell>
                      <TableCell>{r.display_name || "—"}</TableCell>
                      <TableCell className="font-mono text-xs">{r.phone || "—"}</TableCell>
                      <TableCell className="text-muted-foreground">
                        {r.password ? "•••••" : "—"}
                      </TableCell>
                      <TableCell className="text-right">
                        {r._error ? (
                          <StatusPill kind="danger">{r._error}</StatusPill>
                        ) : (
                          <StatusPill status="ok" />
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </DataState>
            {rows!.length > 100 && (
              <div className="border-t p-2 text-center text-xs text-muted-foreground">
                Showing first 100 of {rows!.length} rows.
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Result */}
      {result && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Import complete</CardTitle>
            <CardDescription>
              {result.succeeded} succeeded
              {result.failed > 0 && (
                <span className="text-rose-600 dark:text-rose-400">
                  {" · "}
                  {result.failed} failed
                </span>
              )}
            </CardDescription>
          </CardHeader>
          {result.errors && result.errors.length > 0 && (
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-16">Line</TableHead>
                    <TableHead>Email</TableHead>
                    <TableHead>Error</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {result.errors.map((e, i) => (
                    <TableRow key={i}>
                      <TableCell className="text-muted-foreground">{e.line ?? "—"}</TableCell>
                      <TableCell className="font-mono text-xs">{e.email ?? "—"}</TableCell>
                      <TableCell className="text-rose-600 dark:text-rose-400">
                        {e.message}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          )}
          <CardContent>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={reset}>
                Import another file
              </Button>
              <Link to="/users" className={buttonVariants({ size: "sm" })}>
                View users
              </Link>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
