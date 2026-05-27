import * as React from "react"

import { cn } from "@/lib/utils"

interface ColorPickerProps {
  /** Hex value like "#4F46E5" (3- or 6-digit). Empty string = no color set. */
  value: string
  onChange: (hex: string) => void
  /** Optional preset swatches rendered below the input row. */
  presets?: string[]
  /** Placeholder for the hex text input. */
  placeholder?: string
  disabled?: boolean
  /** Accessible label for the hex input. */
  ariaLabel?: string
  className?: string
}

const HEX_RE = /^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$/

/** A small, curated palette suitable for brand colours. Callers can
 *  pass a custom `presets` array to override. */
const DEFAULT_PRESETS: string[] = [
  "#0ea5e9", // sky
  "#3b82f6", // blue
  "#6366f1", // indigo
  "#8b5cf6", // violet
  "#a855f7", // purple
  "#ec4899", // pink
  "#ef4444", // red
  "#f59e0b", // amber
  "#10b981", // emerald
  "#14b8a6", // teal
  "#0f172a", // slate-900
  "#ffffff", // white
]

function expandShortHex(hex: string): string {
  // #abc → #aabbcc so the native <input type="color"> receives a value
  // it can parse (it only accepts 6-digit).
  if (hex.length === 4) {
    return "#" + hex[1] + hex[1] + hex[2] + hex[2] + hex[3] + hex[3]
  }
  return hex
}

function isValidHex(hex: string): boolean {
  return HEX_RE.test(hex)
}

/**
 * ColorPicker consolidates the (clickable-swatch + hex-text + native
 * picker) combo into one primitive. The swatch is a `<label>` wrapping
 * a hidden `<input type="color">` so clicking it opens the browser's
 * native colour picker; the visible hex text input lives next to it
 * for typing or pasting.
 *
 * `presets` renders below — small clickable squares for the most-used
 * brand colours. Pass an empty array to suppress them.
 */
function ColorPicker({
  value,
  onChange,
  presets = DEFAULT_PRESETS,
  placeholder = "#5b21b6",
  disabled,
  ariaLabel,
  className,
}: ColorPickerProps) {
  const valid = isValidHex(value)
  // Native picker requires 6-digit; expand short hex on the fly.
  const nativeValue = valid ? expandShortHex(value) : "#000000"

  return (
    <div data-slot="color-picker" className={cn("flex flex-col gap-2", className)}>
      <div className="flex items-center gap-2">
        <label
          className={cn(
            "relative grid size-9 shrink-0 cursor-pointer place-items-center overflow-hidden rounded-md border",
            disabled && "pointer-events-none opacity-50",
          )}
          aria-label="Open colour picker"
          style={{
            background: valid
              ? value
              : // Checkered pattern indicates "no colour set"
                "repeating-conic-gradient(#e5e7eb 0% 25%, transparent 0% 50%) 50% / 12px 12px",
          }}
        >
          <input
            type="color"
            value={nativeValue}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => onChange(e.target.value)}
            disabled={disabled}
            className="absolute inset-0 cursor-pointer opacity-0"
          />
        </label>
        <input
          type="text"
          inputMode="text"
          autoComplete="off"
          spellCheck={false}
          value={value}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => onChange(e.target.value)}
          placeholder={placeholder}
          disabled={disabled}
          aria-label={ariaLabel ?? "Hex colour"}
          aria-invalid={value !== "" && !valid}
          className={cn(
            "h-9 w-full min-w-0 rounded-lg border border-input bg-transparent px-2.5 py-1 font-mono text-sm transition-colors outline-none",
            "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50",
            "disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50",
            "aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20",
          )}
        />
      </div>
      {presets.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {presets.map((p) => {
            const isActive = valid && expandShortHex(value).toLowerCase() === expandShortHex(p).toLowerCase()
            return (
              <button
                key={p}
                type="button"
                onClick={() => onChange(p)}
                disabled={disabled}
                aria-label={`Set colour ${p}`}
                aria-pressed={isActive}
                title={p}
                className={cn(
                  "size-5 rounded-md border transition-transform",
                  "hover:scale-110",
                  isActive && "ring-2 ring-ring ring-offset-1",
                  disabled && "pointer-events-none opacity-50",
                )}
                style={{ background: p }}
              />
            )
          })}
        </div>
      )}
    </div>
  )
}

export { ColorPicker }
export type { ColorPickerProps }
