import * as React from "react"
import { ImageIcon, Trash2Icon, UploadCloudIcon } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"

interface LogoUploaderProps {
  /** Current logo source. Can be a public URL or a data URL. Empty means
   *  "no logo set" — the drop-zone is shown. */
  value: string
  /** Called whenever the value changes — either after a file is picked
   *  (data URL) or after the URL text input is edited. */
  onChange: (next: string) => void
  /** Maximum file size in megabytes. Files larger than this are
   *  rejected with an inline error. Defaults to 2 MB. */
  maxSizeMB?: number
  /** Accepted MIME types passed to the file input. Defaults to all images. */
  accept?: string
  /** Disable everything (e.g. while a save is in flight). */
  disabled?: boolean
  /** Optional caption shown beneath the file dropzone. */
  hint?: string
  className?: string
}

/**
 * LogoUploader is a drop-zone + URL fallback for picking a brand logo.
 *
 * Two input paths share the same `value` slot:
 *   - Drop / click a file → read as data URL via FileReader, emit it.
 *   - Paste a URL into the text input → emit the URL string.
 *
 * The caller treats both shapes the same — they're both strings the
 * `<img>` tag understands. When a real upload endpoint ships, swap the
 * `readAsDataURL` path for an upload-then-emit-URL flow without
 * touching call sites.
 */
function LogoUploader({
  value,
  onChange,
  maxSizeMB = 2,
  accept = "image/*",
  disabled,
  hint,
  className,
}: LogoUploaderProps) {
  const [dragOver, setDragOver] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const inputRef = React.useRef<HTMLInputElement>(null)

  const maxBytes = maxSizeMB * 1024 * 1024

  function handleFile(file: File) {
    setError(null)
    if (!file.type.startsWith("image/")) {
      setError("That doesn't look like an image file.")
      return
    }
    if (file.size > maxBytes) {
      setError(`File is larger than ${maxSizeMB} MB.`)
      return
    }
    const reader = new FileReader()
    reader.onload = () => {
      const result = reader.result
      if (typeof result === "string") onChange(result)
    }
    reader.onerror = () => setError("Couldn't read that file.")
    reader.readAsDataURL(file)
  }

  function clearLogo() {
    onChange("")
    setError(null)
    if (inputRef.current) inputRef.current.value = ""
  }

  return (
    <div data-slot="logo-uploader" className={cn("flex flex-col gap-2", className)}>
      {value ? (
        <div className="flex items-start gap-3 rounded-lg border bg-muted/30 p-3">
          <div className="flex size-16 shrink-0 items-center justify-center overflow-hidden rounded-md border bg-background">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={value}
              alt="Logo preview"
              className="h-full w-full object-contain"
              onError={() => setError("Couldn't render that source as an image.")}
            />
          </div>
          <div className="flex flex-1 flex-col gap-1">
            <p className="text-sm font-medium">Logo set</p>
            <p className="line-clamp-1 text-xs text-muted-foreground">
              {value.startsWith("data:") ? "Uploaded file (preview)" : value}
            </p>
            <div className="mt-1 flex gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={disabled}
                onClick={() => inputRef.current?.click()}
              >
                <UploadCloudIcon /> Replace
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={disabled}
                onClick={clearLogo}
              >
                <Trash2Icon /> Remove
              </Button>
            </div>
          </div>
        </div>
      ) : (
        <label
          onDragOver={(e) => {
            e.preventDefault()
            if (!disabled) setDragOver(true)
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault()
            setDragOver(false)
            if (disabled) return
            const file = e.dataTransfer.files[0]
            if (file) handleFile(file)
          }}
          className={cn(
            "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed p-6 text-center transition-colors",
            dragOver ? "border-primary bg-primary/5" : "border-muted-foreground/30",
            disabled && "pointer-events-none opacity-50",
          )}
        >
          <ImageIcon className="size-6 text-muted-foreground" />
          <p className="text-sm font-medium">Drop a logo here</p>
          <p className="text-xs text-muted-foreground">
            PNG, JPG, SVG, or WEBP up to {maxSizeMB} MB
          </p>
        </label>
      )}

      <input
        ref={inputRef}
        type="file"
        accept={accept}
        disabled={disabled}
        className="sr-only"
        onChange={(e) => {
          const f = e.target.files?.[0]
          if (f) handleFile(f)
        }}
      />

      {/* Always-visible URL fallback so existing hosted logos work without
          re-uploading. The two paths share the same value slot. */}
      <div className="flex items-center gap-2">
        <Input
          type="url"
          inputMode="url"
          placeholder="…or paste a logo URL"
          value={value && !value.startsWith("data:") ? value : ""}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => onChange(e.target.value)}
          disabled={disabled}
          aria-label="Logo URL"
        />
      </div>

      {hint && !error && <p className="text-xs text-muted-foreground">{hint}</p>}
      {error && (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
    </div>
  )
}

export { LogoUploader }
export type { LogoUploaderProps }
