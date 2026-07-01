import { cn } from "@qeetrix/ui";

type DotPatternProps = {
  className?: string;
};

export function DotPattern({ className }: DotPatternProps) {
  return (
    <div
      aria-hidden
      className={cn(
        "pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(circle,var(--color-foreground)_1px,transparent_1px)] bg-size-[24px_24px] opacity-[0.06] mask-[radial-gradient(ellipse_at_center,black,transparent_70%)]",
        className,
      )}
    />
  );
}
