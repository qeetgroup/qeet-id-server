import { cn } from "@/lib/cn";
import type { ReactNode } from "react";

type CodeMockupProps = {
  children: ReactNode;
  filename?: string;
  className?: string;
};

export function CodeMockup({ children, filename, className }: CodeMockupProps) {
  return (
    <div
      className={cn(
        "flex flex-col overflow-hidden rounded-xl border border-white/10 bg-[#0d1117] text-xs leading-relaxed text-zinc-200 shadow-xl shadow-black/30",
        className,
      )}
    >
      <div className="flex shrink-0 items-center justify-between border-b border-white/10 bg-white/[0.02] px-3 py-2">
        <div className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-full bg-rose-400/70" />
          <span className="size-2.5 rounded-full bg-amber-400/70" />
          <span className="size-2.5 rounded-full bg-emerald-400/70" />
        </div>
        <span className="font-mono text-[10px] uppercase tracking-widest text-white/40">
          {filename}
        </span>
        <span className="w-10" />
      </div>
      <pre className="flex-1 overflow-x-auto p-4 font-mono">
        <code>{children}</code>
      </pre>
    </div>
  );
}

/* GitHub Dark palette tokens. */
export const Tok = {
  k: ({ children }: { children: ReactNode }) => <span className="text-[#ff7b72]">{children}</span>,
  s: ({ children }: { children: ReactNode }) => <span className="text-[#a5d6ff]">{children}</span>,
  f: ({ children }: { children: ReactNode }) => <span className="text-[#d2a8ff]">{children}</span>,
  v: ({ children }: { children: ReactNode }) => <span className="text-[#ffa657]">{children}</span>,
  t: ({ children }: { children: ReactNode }) => <span className="text-[#7ee787]">{children}</span>,
  p: ({ children }: { children: ReactNode }) => <span className="text-[#79c0ff]">{children}</span>,
  c: ({ children }: { children: ReactNode }) => <span className="text-[#8b949e]">{children}</span>,
  punct: ({ children }: { children: ReactNode }) => (
    <span className="text-[#c9d1d9]">{children}</span>
  ),
};
