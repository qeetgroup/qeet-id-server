import { cn } from "@qeetrix/ui";

type AuroraProps = {
  className?: string;
};

export function Aurora({ className }: AuroraProps) {
  return (
    <div
      aria-hidden
      className={cn(
        "pointer-events-none absolute inset-0 -z-10 overflow-hidden [mask-image:radial-gradient(ellipse_at_center,black_30%,transparent_75%)]",
        className,
      )}
    >
      <div className="absolute left-1/2 top-1/3 -z-10 size-[42rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-[radial-gradient(circle,var(--color-primary)_0%,transparent_60%)] opacity-25 blur-3xl animate-aurora" />
      <div className="absolute left-1/4 top-2/3 -z-10 size-[32rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-[radial-gradient(circle,#7c5cff_0%,transparent_60%)] opacity-20 blur-3xl animate-aurora [animation-delay:-6s]" />
      <div className="absolute left-3/4 top-1/2 -z-10 size-[28rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-[radial-gradient(circle,#22d3ee_0%,transparent_60%)] opacity-15 blur-3xl animate-aurora [animation-delay:-12s]" />
    </div>
  );
}
