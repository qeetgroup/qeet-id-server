import * as React from "react"

import { cn } from "@/lib/utils"

interface OTPInputProps {
  /** Number of digit boxes. Defaults to 6 (RFC 6238 / standard OTP). */
  length?: number
  /** Controlled value — the joined digit string, 0..length chars long. */
  value: string
  onChange: (value: string) => void
  /** Fires when every box is filled with a digit. */
  onComplete?: (value: string) => void
  autoFocus?: boolean
  disabled?: boolean
  className?: string
  "aria-label"?: string
  "aria-invalid"?: boolean | "true" | "false" | "grammar" | "spelling"
}

/**
 * OTPInput renders `length` single-digit boxes used for entering MFA codes
 * (TOTP, email OTP, SMS OTP). It auto-advances on input, supports
 * backspace-to-prev, arrow-key navigation, and pastes a full code into
 * any box. Only digits are accepted; non-digit input is filtered.
 *
 * It is fully controlled — owners pass `value` (the joined string) and
 * `onChange` (called with the new joined string on every edit).
 * `onComplete` fires once when all boxes are filled.
 */
function OTPInput({
  length = 6,
  value,
  onChange,
  onComplete,
  autoFocus,
  disabled,
  className,
  ...aria
}: OTPInputProps) {
  const inputsRef = React.useRef<(HTMLInputElement | null)[]>([])

  const digits = React.useMemo(
    () => Array.from({ length }, (_, i) => value[i] ?? ""),
    [value, length],
  )

  const focusAt = (idx: number) => {
    const i = Math.max(0, Math.min(length - 1, idx))
    const el = inputsRef.current[i]
    if (el) {
      el.focus()
      // Selecting on focus makes overtyping replace the digit cleanly.
      el.select()
    }
  }

  const emit = (next: string[]) => {
    const joined = next.join("")
    onChange(joined)
    if (joined.length === length && next.every((d) => d !== "")) {
      onComplete?.(joined)
    }
  }

  const handleChange = (idx: number) => (e: React.ChangeEvent<HTMLInputElement>) => {
    const raw = e.target.value
    // Strip non-digits; if the input fires for a paste (rare since onPaste
    // pre-empts), take only the last digit so the box never holds >1 char.
    const cleaned = raw.replace(/\D/g, "")
    const digit = cleaned.slice(-1)
    const next = [...digits]
    next[idx] = digit
    emit(next)
    if (digit && idx < length - 1) focusAt(idx + 1)
  }

  const handleKeyDown = (idx: number) => (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace") {
      if (digits[idx] === "" && idx > 0) {
        e.preventDefault()
        const next = [...digits]
        next[idx - 1] = ""
        emit(next)
        focusAt(idx - 1)
      }
      // Else: let the native backspace clear the current digit; onChange
      // will pick that up and propagate.
    } else if (e.key === "ArrowLeft") {
      e.preventDefault()
      focusAt(idx - 1)
    } else if (e.key === "ArrowRight") {
      e.preventDefault()
      focusAt(idx + 1)
    } else if (e.key === "Home") {
      e.preventDefault()
      focusAt(0)
    } else if (e.key === "End") {
      e.preventDefault()
      focusAt(length - 1)
    }
  }

  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    const text = e.clipboardData.getData("text").replace(/\D/g, "")
    if (!text) return
    e.preventDefault()
    const slice = text.slice(0, length)
    const next = Array.from({ length }, (_, i) => slice[i] ?? "")
    emit(next)
    focusAt(Math.min(slice.length, length - 1))
  }

  return (
    <div
      role="group"
      aria-label={aria["aria-label"] ?? "One-time code"}
      className={cn("flex items-center gap-2", className)}
    >
      {digits.map((d, i) => (
        <input
          key={i}
          ref={(el) => {
            inputsRef.current[i] = el
          }}
          type="text"
          inputMode="numeric"
          autoComplete="one-time-code"
          pattern="\d*"
          maxLength={1}
          value={d}
          onChange={handleChange(i)}
          onKeyDown={handleKeyDown(i)}
          onPaste={handlePaste}
          onFocus={(e) => e.currentTarget.select()}
          autoFocus={autoFocus && i === 0}
          disabled={disabled}
          aria-label={`Digit ${i + 1} of ${length}`}
          aria-invalid={aria["aria-invalid"]}
          data-slot="otp-input-digit"
          className={cn(
            "h-12 w-10 rounded-lg border border-input bg-transparent text-center font-mono text-lg outline-none transition-colors",
            "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50",
            "disabled:pointer-events-none disabled:cursor-not-allowed disabled:bg-input/50 disabled:opacity-50",
            "aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20",
            "dark:bg-input/30 dark:disabled:bg-input/80 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40",
            "sm:w-12",
          )}
        />
      ))}
    </div>
  )
}

export { OTPInput }
export type { OTPInputProps }
