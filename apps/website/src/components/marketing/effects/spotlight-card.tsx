"use client";

import { cn } from "@qeetrix/ui";
import { type MouseEvent, type ReactNode, useRef } from "react";

type SpotlightCardProps = {
  children: ReactNode;
  className?: string;
  spotlightColor?: string;
  spotlightSize?: number;
};

export function SpotlightCard({
  children,
  className,
  spotlightColor = "rgba(242,109,14,0.12)",
  spotlightSize = 300,
}: SpotlightCardProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const overlayRef = useRef<HTMLDivElement>(null);

  function onMouseMove(e: MouseEvent<HTMLDivElement>) {
    if (!containerRef.current || !overlayRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    overlayRef.current.style.background = `radial-gradient(${spotlightSize}px circle at ${x}px ${y}px, ${spotlightColor}, transparent 70%)`;
    overlayRef.current.style.opacity = "1";
  }

  function onMouseLeave() {
    if (overlayRef.current) overlayRef.current.style.opacity = "0";
  }

  return (
    <div
      ref={containerRef}
      onMouseMove={onMouseMove}
      onMouseLeave={onMouseLeave}
      className={cn("relative", className)}
    >
      <div
        ref={overlayRef}
        aria-hidden
        className="pointer-events-none absolute inset-0 z-10 opacity-0 transition-opacity duration-300 rounded-[inherit]"
      />
      {children}
    </div>
  );
}
