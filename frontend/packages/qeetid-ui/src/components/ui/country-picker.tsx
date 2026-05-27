import * as React from "react"

import { cn } from "@/lib/utils"

interface CountryPickerProps {
  /** ISO 3166-1 alpha-2 code (e.g. "US", "FR"). Empty = no selection. */
  value: string
  onChange: (next: string) => void
  /** Optional placeholder when value is empty. */
  placeholder?: string
  /** Localisation override; defaults to the user's browser locale. */
  locale?: string
  disabled?: boolean
  ariaLabel?: string
  className?: string
}

/** ISO 3166-1 alpha-2 codes for all UN-recognised states + a few common
 *  dependencies. Hand-maintained — Intl doesn't expose this list. */
const ISO_CODES: string[] = [
  "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
  "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR",
  "BS", "BT", "BW", "BY", "BZ",
  "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV",
  "CW", "CX", "CY", "CZ",
  "DE", "DJ", "DK", "DM", "DO", "DZ",
  "EC", "EE", "EG", "EH", "ER", "ES", "ET",
  "FI", "FJ", "FK", "FM", "FO", "FR",
  "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GT",
  "GU", "GW", "GY",
  "HK", "HN", "HR", "HT", "HU",
  "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT",
  "JE", "JM", "JO", "JP",
  "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ",
  "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY",
  "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR",
  "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ",
  "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ",
  "OM",
  "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY",
  "QA",
  "RE", "RO", "RS", "RU", "RW",
  "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR",
  "SS", "ST", "SV", "SX", "SY", "SZ",
  "TC", "TD", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ",
  "UA", "UG", "US", "UY", "UZ",
  "VA", "VC", "VE", "VG", "VI", "VN", "VU",
  "WF", "WS",
  "YE", "YT",
  "ZA", "ZM", "ZW",
]

interface CountryOption {
  code: string
  name: string
}

function buildOptions(locale: string | undefined): CountryOption[] {
  let displayNames: Intl.DisplayNames | null = null
  try {
    displayNames = new Intl.DisplayNames(locale ? [locale] : undefined, { type: "region" })
  } catch {
    displayNames = null
  }
  const out = ISO_CODES.map((code) => ({
    code,
    name: displayNames?.of(code) ?? code,
  }))
  out.sort((a, b) => a.name.localeCompare(b.name))
  return out
}

/**
 * CountryPicker renders a native `<select>` populated from ISO 3166-1
 * alpha-2 codes, with localised display names from
 * `Intl.DisplayNames`. Native selects keep the bundle tiny and a11y
 * perfect; users get type-to-jump in every browser.
 *
 * Pass a `locale` (e.g. "fr-FR") to override the user's browser
 * default. Emits the alpha-2 code on change.
 */
function CountryPicker({
  value,
  onChange,
  placeholder = "Select country",
  locale,
  disabled,
  ariaLabel,
  className,
}: CountryPickerProps) {
  const options = React.useMemo(() => buildOptions(locale), [locale])

  return (
    <select
      value={value}
      onChange={(e: React.ChangeEvent<HTMLSelectElement>) => onChange(e.target.value)}
      disabled={disabled}
      aria-label={ariaLabel ?? "Country"}
      data-slot="country-picker"
      className={cn(
        "h-9 w-full min-w-0 rounded-lg border border-input bg-transparent px-2.5 py-1 text-sm outline-none transition-colors",
        "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50",
        "disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
    >
      <option value="">{placeholder}</option>
      {options.map((o) => (
        <option key={o.code} value={o.code}>
          {o.name}
        </option>
      ))}
    </select>
  )
}

export { CountryPicker, ISO_CODES as COUNTRY_CODES }
export type { CountryPickerProps }
