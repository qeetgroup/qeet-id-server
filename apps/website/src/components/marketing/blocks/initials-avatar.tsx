import { Avatar, AvatarFallback, cn } from "@qeetrix/ui";

/**
 * Deterministic monochrome initials avatar. Derives 1–2 initials and a
 * stable tone from the name so the same person always renders the same
 * way — no remote photos, no layout shift. Honest by design.
 */
export interface InitialsAvatarProps {
  name: string;
  className?: string;
  size?: "sm" | "default" | "lg";
}

const tones = [
  "bg-muted text-foreground/80",
  "bg-foreground/10 text-foreground",
  "bg-primary/15 text-primary",
  "bg-foreground text-background",
  "bg-muted-foreground/15 text-foreground/80",
] as const;

function initialsFor(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "·";
  if (parts.length === 1) return parts[0]!.slice(0, 2).toUpperCase();
  return `${parts[0]![0]}${parts[parts.length - 1]![0]}`.toUpperCase();
}

function toneFor(name: string): string {
  let hash = 0;
  for (let i = 0; i < name.length; i++) hash = (hash * 31 + name.charCodeAt(i)) >>> 0;
  return tones[hash % tones.length]!;
}

const rootSize: Record<NonNullable<InitialsAvatarProps["size"]>, string> = {
  sm: "size-7",
  default: "size-10",
  lg: "size-12",
};

const textSize: Record<NonNullable<InitialsAvatarProps["size"]>, string> = {
  sm: "text-[10px]",
  default: "text-xs",
  lg: "text-sm",
};

export function InitialsAvatar({ name, className, size = "default" }: InitialsAvatarProps) {
  return (
    <Avatar className={cn(rootSize[size], className)} role="img" aria-label={`${name} avatar`}>
      <AvatarFallback
        className={cn("font-display font-semibold tracking-tight", textSize[size], toneFor(name))}
      >
        {initialsFor(name)}
      </AvatarFallback>
    </Avatar>
  );
}
