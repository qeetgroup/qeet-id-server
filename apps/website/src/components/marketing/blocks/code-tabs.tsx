"use client";

import { CodeBlock, type CodeLanguage, cn } from "@qeetrix/ui";
import { useId, useState } from "react";

export interface CodeTab {
  /** Label shown on the tab (e.g. "TypeScript"). */
  label: string;
  /** The qeetrix CodeBlock language for highlighting. */
  language: CodeLanguage;
  /** Raw code string. */
  value: string;
  /** Optional caption (e.g. filename). */
  caption?: string;
}

export interface CodeTabsProps {
  tabs: CodeTab[];
  className?: string;
}

export function CodeTabs({ tabs, className }: CodeTabsProps) {
  const [active, setActive] = useState(0);
  const baseId = useId();
  const current = tabs[active]!;

  return (
    <div className={cn("flex flex-col gap-3", className)}>
      <div role="tablist" aria-label="Code language" className="flex flex-wrap gap-1">
        {tabs.map((tab, i) => {
          const selected = i === active;
          return (
            <button
              key={tab.label}
              type="button"
              role="tab"
              id={`${baseId}-tab-${i}`}
              aria-selected={selected}
              aria-controls={`${baseId}-panel-${i}`}
              onClick={() => setActive(i)}
              className={cn(
                "rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                selected
                  ? "bg-foreground text-background"
                  : "text-muted-foreground hover:bg-accent hover:text-foreground",
              )}
            >
              {tab.label}
            </button>
          );
        })}
      </div>
      <div
        role="tabpanel"
        id={`${baseId}-panel-${active}`}
        aria-labelledby={`${baseId}-tab-${active}`}
      >
        <CodeBlock
          value={current.value}
          language={current.language}
          caption={current.caption}
        />
      </div>
    </div>
  );
}
