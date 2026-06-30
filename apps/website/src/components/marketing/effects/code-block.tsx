import { cn } from "@qeetrix/ui";
import type { ReactNode } from "react";

/**
 * Tiny IDE-style code surface used by marketing sections.
 * Always dark — even in light mode — so it reads as a terminal/editor preview.
 */
type CodeBlockProps = {
  children: ReactNode;
  filename?: string;
  language?: string;
  className?: string;
};

export function CodeBlock({ children, filename, language, className }: CodeBlockProps) {
  return (
    <div
      className={cn(
        "flex h-full flex-col overflow-hidden rounded-xl border border-white/10 bg-[#0d1117] text-xs leading-relaxed text-zinc-200 shadow-xl shadow-black/30",
        className,
      )}
    >
      <div className="flex shrink-0 items-center justify-between border-b border-white/10 bg-white/2 px-3 py-2">
        <div className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-full bg-rose-400/70" />
          <span className="size-2.5 rounded-full bg-amber-400/70" />
          <span className="size-2.5 rounded-full bg-emerald-400/70" />
        </div>
        <span className="font-mono text-[10px] uppercase tracking-widest text-white/40">
          {filename ?? language}
        </span>
        <span className="w-10" />
      </div>
      <pre className="flex-1 overflow-x-auto p-4 font-mono [font-variant-ligatures:contextual] font-features-['calt'_1,'ss01'_1,'ss02'_1,'ss03'_1]">
        <code>{children}</code>
      </pre>
    </div>
  );
}

/* ===== Token primitives (GitHub Dark palette) ===== */
export const Tok = {
  k: ({ children }: { children: ReactNode }) => (
    <span className="text-[#ff7b72]">{children}</span> // keyword
  ),
  s: ({ children }: { children: ReactNode }) => (
    <span className="text-[#a5d6ff]">{children}</span> // string
  ),
  n: ({ children }: { children: ReactNode }) => (
    <span className="text-[#79c0ff]">{children}</span> // number / constant
  ),
  f: ({ children }: { children: ReactNode }) => (
    <span className="text-[#d2a8ff]">{children}</span> // function / method
  ),
  v: ({ children }: { children: ReactNode }) => (
    <span className="text-[#ffa657]">{children}</span> // variable / identifier
  ),
  t: ({ children }: { children: ReactNode }) => (
    <span className="text-[#7ee787]">{children}</span> // JSX tag / type
  ),
  p: ({ children }: { children: ReactNode }) => (
    <span className="text-[#79c0ff]">{children}</span> // prop / attribute
  ),
  c: ({ children }: { children: ReactNode }) => (
    <span className="text-[#8b949e]">{children}</span> // comment / dim
  ),
  punct: ({ children }: { children: ReactNode }) => (
    <span className="text-[#c9d1d9]">{children}</span> // brackets / punctuation
  ),
};
