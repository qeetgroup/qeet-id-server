import { cn } from "@qeetrix/ui";
import type { ComponentType, SVGProps } from "react";

type BrandIcon = ComponentType<{ className?: string } & SVGProps<SVGSVGElement>>;

/**
 * Uniform monochrome brand lockup. With an `icon`, renders the real brand
 * mark (desaturated to grey so mixed logos read as one calm wall, colouring
 * in on hover); without one, falls back to a designed geometric glyph. Pair
 * many of these in a grid or marquee for a premium logo wall.
 */
export interface LogoLockupProps {
  name: string;
  /** Real brand mark (e.g. from `@thesvg/react`). Falls back to a glyph when omitted. */
  icon?: BrandIcon;
  className?: string;
}

// Deterministic glyph index so each name keeps its mark across renders.
function glyphIndex(name: string): number {
  let hash = 0;
  for (let i = 0; i < name.length; i++) hash = (hash * 31 + name.charCodeAt(i)) >>> 0;
  return hash % 4;
}

function LockupGlyph({ name }: { name: string }) {
  const idx = glyphIndex(name);
  return (
    <span
      aria-hidden
      className="grid size-5 shrink-0 place-items-center rounded-[5px] border border-current/30"
    >
      {idx === 0 && <span className="size-2 rounded-full bg-current" />}
      {idx === 1 && <span className="size-2 rounded-[2px] bg-current" />}
      {idx === 2 && <span className="size-2 rotate-45 bg-current" />}
      {idx === 3 && <span className="h-2 w-0.5 bg-current" />}
    </span>
  );
}

export function LogoLockup({ name, icon: Icon, className }: LogoLockupProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 text-muted-foreground transition-colors hover:text-foreground focus-visible:text-foreground",
        className,
      )}
    >
      {Icon ? (
        // Native brand colors, always on.
        <Icon aria-hidden className="size-6 shrink-0" />
      ) : (
        <LockupGlyph name={name} />
      )}
      <span className="font-display text-lg font-semibold tracking-tight">{name}</span>
    </span>
  );
}

export interface LogoWallProps {
  names: string[];
  className?: string;
}

export function LogoWall({ names, className }: LogoWallProps) {
  return (
    <div
      className={cn(
        "grid grid-cols-2 items-center gap-x-8 gap-y-8 sm:grid-cols-3 lg:grid-cols-4",
        className,
      )}
    >
      {names.map((name) => (
        <div key={name} className="flex justify-center">
          <LogoLockup name={name} />
        </div>
      ))}
    </div>
  );
}
