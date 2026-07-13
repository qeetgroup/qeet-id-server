"use client";

import { cn } from "@qeetrix/ui";
import { type MouseEvent, type ReactNode, useRef } from "react";

type GlowCardProps = {
  children: ReactNode;
  className?: string;
  glowColor?: string;
  glowSize?: number;
};

/** Cursor-following glow overlay — adds a warm radial highlight that tracks the pointer. */
export function GlowCard({
  children,
  className,
  glowColor = "rgba(242,109,14,0.18)",
  glowSize = 380,
}: GlowCardProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const glowRef = useRef<HTMLDivElement>(null);

  function onMouseMove(e: MouseEvent<HTMLDivElement>) {
    if (!containerRef.current || !glowRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    glowRef.current.style.background = `radial-gradient(${glowSize}px circle at ${x}px ${y}px, ${glowColor}, transparent 65%)`;
    glowRef.current.style.opacity = "1";
  }

  function onMouseLeave() {
    if (glowRef.current) glowRef.current.style.opacity = "0";
  }

  return (
    <div
      ref={containerRef}
      onMouseMove={onMouseMove}
      onMouseLeave={onMouseLeave}
      className={cn("relative overflow-hidden", className)}
    >
      <div
        ref={glowRef}
        aria-hidden
        className="pointer-events-none absolute inset-0 z-20 opacity-0 transition-opacity duration-500 rounded-[inherit]"
      />
      {children}
    </div>
  );
}
