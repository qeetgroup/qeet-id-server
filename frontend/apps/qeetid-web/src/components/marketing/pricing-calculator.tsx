"use client";

import { Slider } from "@qeetid/ui";
import { useMemo, useState } from "react";

import { ButtonLink } from "@/components/marketing/button-link";

// Pricing knobs — keep aligned with the static tier cards on this page.
// We hard-code them so the marketing site stays deployable without
// reaching the backend; if pricing ever moves server-side, swap to a
// fetched config and degrade the calculator gracefully.
const FREE_CAP = 5_000;
const PRO_BASE = 99;
const PRO_INCLUDED = 50_000;
const PRO_PER_MAU = 0.02;
const ENTERPRISE_THRESHOLD = 500_000;

// Log-scale slider. A linear scale crushes Free (5K) and Pro (50K)
// into the first 5% of the track and is unusable. Log keeps every
// order of magnitude equally spaced.
const MIN_MAU = 100;
const MAX_MAU = 1_000_000;
const EXP = Math.log10(MAX_MAU / MIN_MAU);

function sliderToMau(s: number) {
  return MIN_MAU * Math.pow(10, (s / 100) * EXP);
}

function mauToSlider(m: number) {
  if (m <= MIN_MAU) return 0;
  if (m >= MAX_MAU) return 100;
  return (Math.log10(m / MIN_MAU) / EXP) * 100;
}

// Round to two significant figures so the read-out doesn't flicker
// digits as the slider scrubs.
function roundFriendly(n: number) {
  if (n < 100) return Math.round(n);
  const order = Math.floor(Math.log10(n));
  const step = Math.pow(10, Math.max(0, order - 1));
  return Math.round(n / step) * step;
}

interface ComputedPlan {
  name: "Free" | "Pro" | "Enterprise";
  blurb: string;
  monthly: number | null;
  breakdown?: string;
  cta: { label: string; href: string };
}

function computePlan(mau: number): ComputedPlan {
  if (mau <= FREE_CAP) {
    return {
      name: "Free",
      blurb: "Your usage fits in the free tier — no card required.",
      monthly: 0,
      cta: { label: "Start free", href: "/sign-up" },
    };
  }
  if (mau > ENTERPRISE_THRESHOLD) {
    return {
      name: "Enterprise",
      blurb: "We'll size a contract to your traffic and compliance needs.",
      monthly: null,
      cta: { label: "Talk to sales", href: "/contact" },
    };
  }
  const overage = Math.max(0, mau - PRO_INCLUDED);
  const monthly = PRO_BASE + overage * PRO_PER_MAU;
  const breakdown =
    overage === 0
      ? `$${PRO_BASE} base · first ${PRO_INCLUDED.toLocaleString("en-US")} MAU included`
      : `$${PRO_BASE} base + $${PRO_PER_MAU.toFixed(2)} × ${overage.toLocaleString("en-US")} MAU over ${PRO_INCLUDED.toLocaleString("en-US")}`;
  return {
    name: "Pro",
    blurb: "Predictable per-MAU pricing.",
    monthly,
    breakdown,
    cta: { label: "Start 14-day trial", href: "/sign-up?plan=pro" },
  };
}

const PRESETS = [1_000, 10_000, 100_000, 1_000_000];

function formatPreset(n: number) {
  if (n >= 1_000_000) return `${n / 1_000_000}M`;
  if (n >= 1_000) return `${n / 1_000}K`;
  return `${n}`;
}

export function PricingCalculator() {
  const [sliderValue, setSliderValue] = useState(() => mauToSlider(25_000));
  const mau = useMemo(() => roundFriendly(sliderToMau(sliderValue)), [sliderValue]);
  const plan = computePlan(mau);

  function setMau(value: number) {
    setSliderValue(mauToSlider(Math.max(MIN_MAU, Math.min(MAX_MAU, value))));
  }

  return (
    <section className="border-b border-border/60">
      <div className="mx-auto max-w-5xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <div className="mx-auto max-w-2xl text-center">
          <p className="text-sm font-medium uppercase tracking-widest text-primary">
            Estimate your bill
          </p>
          <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            How much will Qeet ID cost you?
          </h2>
          <p className="mt-3 text-muted-foreground">
            Drag the slider to your expected monthly active users. The estimate covers core authentication; add-ons quoted separately.
          </p>
        </div>

        <div className="mt-12 grid gap-6 rounded-2xl border border-border/60 bg-background p-6 sm:p-10 lg:grid-cols-[3fr_2fr] lg:gap-10">
          {/* Slider column */}
          <div>
            <label className="text-sm font-medium text-muted-foreground" htmlFor="calc-mau">
              Monthly active users
            </label>
            <div className="mt-1 flex items-baseline gap-3">
              <input
                id="calc-mau"
                className="w-44 border-0 bg-transparent font-display text-4xl font-semibold tracking-tight outline-none [appearance:textfield] focus-visible:ring-0 [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none sm:text-5xl"
                type="number"
                inputMode="numeric"
                min={MIN_MAU}
                max={MAX_MAU}
                value={mau}
                onChange={(e) => {
                  const next = Number(e.target.value);
                  if (Number.isFinite(next)) setMau(next);
                }}
                aria-label="Monthly active users"
              />
              <span className="text-sm text-muted-foreground">MAU / month</span>
            </div>

            <div className="mt-8">
              <Slider
                value={[sliderValue]}
                onValueChange={(values) =>
                  setSliderValue(
                    Array.isArray(values) ? (values[0] ?? 0) : (values as number),
                  )
                }
                min={0}
                max={100}
                step={0.5}
                aria-label="MAU slider"
              />
              <div className="mt-4 flex justify-between gap-2 text-xs text-muted-foreground">
                {PRESETS.map((p) => (
                  <button
                    key={p}
                    type="button"
                    className="rounded-md px-2 py-1 transition-colors hover:bg-muted hover:text-foreground"
                    onClick={() => setMau(p)}
                  >
                    {formatPreset(p)}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Result column */}
          <div className="rounded-2xl border border-border/60 bg-muted/20 p-6 sm:p-8">
            <div className="flex items-center justify-between">
              <span className="rounded-full bg-primary/15 px-2.5 py-1 text-xs font-medium uppercase tracking-wider text-primary">
                {plan.name}
              </span>
              {plan.monthly !== null && (
                <span className="text-xs text-muted-foreground">USD · billed monthly</span>
              )}
            </div>

            <div className="mt-4 flex items-baseline gap-2">
              {plan.monthly === null ? (
                <span className="font-display text-4xl font-semibold tracking-tight">
                  Custom
                </span>
              ) : (
                <>
                  <span className="font-display text-5xl font-semibold tracking-tight">
                    {plan.monthly === 0
                      ? "$0"
                      : `$${plan.monthly.toLocaleString("en-US", {
                          minimumFractionDigits: 0,
                          maximumFractionDigits: 2,
                        })}`}
                  </span>
                  <span className="text-sm text-muted-foreground">/ mo</span>
                </>
              )}
            </div>

            <p className="mt-3 text-sm text-muted-foreground">{plan.blurb}</p>

            {plan.breakdown && (
              <p className="mt-4 rounded-lg border border-border/60 bg-background px-3 py-2 text-xs text-muted-foreground">
                {plan.breakdown}
              </p>
            )}

            {plan.monthly !== null && plan.monthly > 0 && (
              <p className="mt-3 text-xs text-muted-foreground">
                ≈{" "}
                <strong className="text-foreground">
                  ${(plan.monthly * 12).toLocaleString("en-US", {
                    minimumFractionDigits: 0,
                    maximumFractionDigits: 0,
                  })}
                </strong>{" "}
                / year
              </p>
            )}

            <div className="mt-6">
              <ButtonLink href={plan.cta.href} className="w-full">
                {plan.cta.label}
              </ButtonLink>
            </div>
          </div>
        </div>

        <p className="mt-4 text-center text-xs text-muted-foreground">
          Estimates are illustrative. Volume discounts apply above 250,000 MAU — talk to sales.
        </p>
      </div>
    </section>
  );
}
