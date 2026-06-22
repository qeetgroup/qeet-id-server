"use client";

import { useId, type CSSProperties, type ReactNode } from "react";

import { usePaths } from "./context.js";

// Sends the browser to a hosted auth URL, preserving where to come back to.
// (Kept local so this module has no dependency on the rest of the SDK beyond
// the paths context — the button stays drop-in for any consumer.)
function navigate(url: string, returnTo?: string): void {
  const u = new URL(url, window.location.origin);
  if (returnTo !== undefined) u.searchParams.set("return_to", returnTo);
  window.location.href = u.toString();
}

// ---------------------------------------------------------------------------
// Qeet mark — self-contained inline SVG (no @qeetrix/* dependency, so the SDK
// ships zero runtime deps). The light/dark artwork differ ONLY in the bowl
// fill; the brand orange is shared. Path data mirrors @qeetrix/brand's
// QeetLogoOnLight / QeetLogoOnDark (viewBox 1254×1254 "Q" app-icon mark).
// ---------------------------------------------------------------------------
function markInner(maskId: string, bowlFill: string): string {
  return `<defs><mask id="${maskId}" maskUnits="userSpaceOnUse"><rect width="1254" height="1254" fill="#FFFFFF"/><path fill="#000000" d="M669.964722,338.242981 C714.535645,351.395386 751.471863,375.501129 779.470825,412.042328 C814.503479,457.763184 828.529907,509.627594 821.508301,567.354248 C815.037964,614.333862 796.163635,655.232849 763.035339,688.671509 C715.514587,736.637695 657.793396,758.218994 590.453552,749.188904 C504.824402,737.706116 436.176788,675.264038 417.429352,590.163330 C398.281219,503.243683 423.564056,429.604553 493.036591,373.787628 C542.333557,334.180542 599.844727,323.023224 661.836060,336.080780 C664.430725,336.627319 666.966248,337.454285 669.964722,338.242981 z"/></mask></defs><path mask="url(#${maskId})" fill="${bowlFill}" d="M821.791687,894.018799 C803.326172,903.166809 785.336975,913.478882 766.312927,921.261658 C682.977112,955.354797 597.577454,960.575989 510.776794,936.458923 C427.137451,913.220154 358.319214,867.022827 303.655487,799.771240 C259.619385,745.594543 231.852402,683.929749 219.855377,615.135681 C205.246201,531.363037 215.390701,450.569489 250.641022,373.361603 C287.752838,292.076569 346.057434,229.640503 423.650269,185.486679 C489.535767,147.994873 560.685242,131.387634 636.355042,134.347610 C667.607117,135.570114 698.193970,141.258041 728.247498,149.842102 C729.508179,150.202209 730.704346,150.788620 731.848389,151.967499 C730.448730,152.746170 729.071960,153.118286 727.822754,152.863968 C709.200012,149.072678 691.179749,151.872894 674.192566,159.455490 C609.452271,188.353607 598.711670,273.967438 647.019897,320.610840 C654.005493,327.355682 662.567566,332.467743 669.964722,338.242981 C666.966248,337.454285 664.430725,336.627319 661.836060,336.080780 C599.844727,323.023224 542.333557,334.180542 493.036591,373.787628 C423.564056,429.604553 398.281219,503.243683 417.429352,590.163330 C436.176788,675.264038 504.824402,737.706116 590.453552,749.188904 C657.793396,758.218994 715.514587,736.637695 763.035339,688.671509 C796.163635,655.232849 815.037964,614.333862 821.583984,568.151245 C821.813477,570.053894 822.135437,571.531555 822.135864,573.009338 C822.152954,633.669861 822.122437,694.330322 822.139038,754.990845 C822.151672,800.985046 822.219727,846.979187 822.106567,893.217285 C821.897339,893.647034 821.844543,893.832886 821.791687,894.018799 z"/><path fill="#F26D0E" d="M822.263123,892.973389 C822.219727,846.979187 822.151672,800.985046 822.139038,754.990845 C822.122437,694.330322 822.152954,633.669861 822.135864,573.009338 C822.135437,571.531555 821.813477,570.053894 821.565674,567.779114 C828.529907,509.627594 814.503479,457.763184 779.470825,412.042328 C751.471863,375.501129 714.535645,351.395386 670.400085,338.335388 C662.567566,332.467743 654.005493,327.355682 647.019897,320.610840 C598.711670,273.967438 609.452271,188.353607 674.192566,159.455490 C691.179749,151.872894 709.200012,149.072678 727.822754,152.863968 C729.071960,153.118286 730.448730,152.746170 731.992310,152.316010 C769.401550,160.954422 803.019836,177.923462 834.791809,198.657364 C880.962646,228.787796 919.463745,266.834351 950.460815,312.497620 C982.820740,360.168488 1003.902954,412.329163 1013.963745,469.046661 C1020.018982,503.183136 1020.544678,537.589294 1019.593262,572.806763 C1019.448914,575.015015 1019.590332,576.503357 1019.731812,577.991638 C1019.772949,580.350159 1019.814148,582.708679 1019.428955,585.628662 C1017.683411,593.105652 1016.613953,600.080200 1014.998474,606.925842 C1009.980408,628.190918 1005.808533,649.733887 999.348572,670.561157 C990.918884,697.739197 978.245422,723.197205 964.169678,747.999512 C946.413818,779.286499 923.983276,806.907410 899.392212,832.849548 C890.630920,842.092285 880.599915,850.155457 870.943115,858.519897 C855.853760,871.589722 839.671936,883.159241 822.263123,892.973389 z"/><path fill="#D85301" d="M822.106567,893.217285 C839.671936,883.159241 855.853760,871.589722 870.943115,858.519897 C880.599915,850.155457 890.630920,842.092285 899.392212,832.849548 C923.983276,806.907410 946.413818,779.286499 964.169678,747.999512 C978.245422,723.197205 990.918884,697.739197 999.348572,670.561157 C1005.808533,649.733887 1009.980408,628.190918 1014.998474,606.925842 C1016.613953,600.080200 1017.683411,593.105652 1019.364136,586.065613 C1019.808838,604.428406 1019.960144,622.915649 1019.964478,641.402893 C1019.996887,779.531555 1020.306824,917.661377 1019.819763,1055.788208 C1019.679565,1095.540405 1004.006104,1128.543701 969.487183,1150.236328 C923.479797,1179.148682 863.557739,1162.918457 837.012451,1115.253418 C826.966858,1097.215454 822.142151,1077.902100 822.083740,1057.398804 C821.929504,1003.248413 821.950806,949.097534 821.846924,894.482788 C821.844543,893.832886 821.897339,893.647034 822.106567,893.217285 z"/><path fill="#D85301" d="M1019.828918,577.584717 C1019.590332,576.503357 1019.448914,575.015015 1019.526367,573.272095 C1019.805603,574.404175 1019.865845,575.791016 1019.828918,577.584717 z"/>`;
}

function QeetMark({ tone, size, className }: { tone: "light" | "dark"; size: number; className?: string }) {
  // Unique mask id per instance so multiple buttons on a page don't collide.
  const maskId = `qbowl-${useId().replace(/:/g, "")}-${tone}`;
  // tone="light" = dark artwork for light surfaces; tone="dark" = light artwork for dark surfaces.
  const bowlFill = tone === "dark" ? "#FCFCFC" : "#0A0A0A";
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 1254 1254"
      width={size}
      height={size}
      className={className}
      aria-hidden
      focusable={false}
      style={{ display: "block", flex: "0 0 auto" }}
      dangerouslySetInnerHTML={{ __html: markInner(maskId, bowlFill) }}
    />
  );
}

// ---------------------------------------------------------------------------
// Branded button base
// ---------------------------------------------------------------------------
type Theme = "light" | "dark" | "auto";

export interface QeetAuthButtonProps {
  /** Color scheme. "light" = white button, "dark" = dark button, "auto" = follow prefers-color-scheme. Default "light". */
  theme?: Theme;
  /** Corner style. Default "rounded". */
  shape?: "rounded" | "pill";
  /** Stretch to the container width. Default true. */
  fullWidth?: boolean;
  /** Override the button text. */
  children?: ReactNode;
  className?: string;
  style?: CSSProperties;
  /** Path to return to after the flow completes (defaults to the current location). */
  returnTo?: string;
  disabled?: boolean;
}

const LIGHT = { bg: "#ffffff", color: "#1f1f1f", border: "rgba(0,0,0,0.16)" };
const DARK = { bg: "#18181b", color: "#e8e8ea", border: "rgba(255,255,255,0.16)" };

function scopedCss(cls: string, theme: Theme): string {
  const ring = `.${cls}:focus-visible{outline:2px solid #F26D0E;outline-offset:2px}`;
  const off = `.${cls}:disabled{opacity:.55;cursor:default}`;
  const lightHover = `.${cls}:hover:not(:disabled){background:#f7f8f8;border-color:rgba(0,0,0,.24)}`;
  const darkHover = `.${cls}:hover:not(:disabled){background:#232327;border-color:rgba(255,255,255,.26)}`;
  if (theme === "light") return `${lightHover}${ring}${off}`;
  if (theme === "dark") return `${darkHover}${ring}${off}`;
  // auto: light by default (inline), dark under prefers-color-scheme. !important
  // is required to beat the inline base styles set on the element.
  return (
    `${lightHover}${ring}${off}.${cls} .qmark-dark{display:none}` +
    `@media (prefers-color-scheme:dark){` +
    `.${cls}{background:${DARK.bg}!important;color:${DARK.color}!important;border-color:${DARK.border}!important}` +
    `.${cls}:hover:not(:disabled){background:#232327!important;border-color:rgba(255,255,255,.26)!important}` +
    `.${cls} .qmark-light{display:none}.${cls} .qmark-dark{display:block}}`
  );
}

function QeetAuthButton({
  label,
  onClick,
  theme = "light",
  shape = "rounded",
  fullWidth = true,
  children,
  className,
  style,
  disabled,
}: QeetAuthButtonProps & { label: string; onClick: () => void }) {
  const cls = `qbtn-${useId().replace(/:/g, "")}`;
  const tokens = theme === "dark" ? DARK : LIGHT; // "auto" starts light, flips via CSS
  const base: CSSProperties = {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    gap: 10,
    width: fullWidth ? "100%" : "auto",
    boxSizing: "border-box",
    padding: "10px 16px",
    border: "1px solid",
    borderColor: tokens.border,
    borderRadius: shape === "pill" ? 9999 : 8,
    background: tokens.bg,
    color: tokens.color,
    font: "500 14px/1 system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif",
    cursor: "pointer",
    userSelect: "none",
    WebkitTapHighlightColor: "transparent",
    transition: "background .15s ease, border-color .15s ease",
    ...style,
  };

  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: scopedCss(cls, theme) }} />
      <button
        type="button"
        className={[cls, className].filter(Boolean).join(" ")}
        style={base}
        disabled={disabled}
        aria-label={label}
        onClick={onClick}
      >
        {theme === "auto" ? (
          <>
            <QeetMark tone="light" size={18} className="qmark-light" />
            <QeetMark tone="dark" size={18} className="qmark-dark" />
          </>
        ) : (
          <QeetMark tone={theme} size={18} />
        )}
        <span>{children ?? label}</span>
      </button>
    </>
  );
}

/** "Sign in with Qeet" — redirects to the hosted Qeet login. */
export function SignInWithQeet(props: QeetAuthButtonProps) {
  const { loginUrl } = usePaths();
  const returnTo = props.returnTo ?? defaultReturnTo();
  return <QeetAuthButton {...props} label="Sign in with Qeet" onClick={() => navigate(loginUrl, returnTo)} />;
}

/** "Sign up with Qeet" — redirects to the hosted Qeet sign-up. */
export function SignUpWithQeet(props: QeetAuthButtonProps) {
  const { signUpUrl } = usePaths();
  const returnTo = props.returnTo ?? defaultReturnTo();
  return <QeetAuthButton {...props} label="Sign up with Qeet" onClick={() => navigate(signUpUrl, returnTo)} />;
}

/** "Continue with Qeet" — neutral label covering both sign-in and sign-up. */
export function ContinueWithQeet(props: QeetAuthButtonProps) {
  const { loginUrl } = usePaths();
  const returnTo = props.returnTo ?? defaultReturnTo();
  return <QeetAuthButton {...props} label="Continue with Qeet" onClick={() => navigate(loginUrl, returnTo)} />;
}

function defaultReturnTo(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return window.location.pathname + window.location.search;
}
