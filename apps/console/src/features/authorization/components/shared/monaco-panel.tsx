import { CodeBlock } from "@qeetrix/ui";
import { lazy, Suspense, useEffect, useState } from "react";

import { ClientOnly } from "./client-only";

// Monaco is heavy and client-only, so it is code-split and lazily loaded. Until
// it mounts (and during SSR), we render the read-only qeetrix CodeBlock so the
// content is always visible and copyable — a graceful, dependency-safe fallback.
const MonacoEditor = lazy(() => import("@monaco-editor/react"));

function useIsDark(): boolean {
  const [dark, setDark] = useState(false);
  useEffect(() => {
    const el = document.documentElement;
    const update = () => setDark(el.classList.contains("dark"));
    update();
    const obs = new MutationObserver(update);
    obs.observe(el, { attributes: true, attributeFilter: ["class"] });
    return () => obs.disconnect();
  }, []);
  return dark;
}

export interface MonacoPanelProps {
  value: string;
  language?: "json" | "yaml" | "plaintext";
  readOnly?: boolean;
  onChange?: (value: string) => void;
  height?: number | string;
  className?: string;
  /** Label for assistive tech when editable. */
  ariaLabel?: string;
}

export function MonacoPanel({
  value,
  language = "json",
  readOnly = true,
  onChange,
  height = 320,
  className,
  ariaLabel,
}: MonacoPanelProps) {
  const dark = useIsDark();
  const heightStr = typeof height === "number" ? `${height}px` : height;
  const fallback = (
    <CodeBlock
      value={value}
      language={language === "json" ? "json" : "text"}
      maxHeight={heightStr}
    />
  );

  return (
    <ClientOnly fallback={fallback}>
      <Suspense fallback={fallback}>
        <div className={className} style={{ height: heightStr }} aria-label={ariaLabel}>
          <MonacoEditor
            height="100%"
            language={language}
            theme={dark ? "vs-dark" : "light"}
            value={value}
            loading={fallback}
            onChange={(v) => onChange?.(v ?? "")}
            options={{
              readOnly,
              domReadOnly: readOnly,
              minimap: { enabled: false },
              fontSize: 12,
              lineNumbers: "on",
              scrollBeyondLastLine: false,
              automaticLayout: true,
              tabSize: 2,
              wordWrap: "on",
              padding: { top: 10, bottom: 10 },
              renderLineHighlight: readOnly ? "none" : "line",
              overviewRulerLanes: 0,
              scrollbar: { alwaysConsumeMouseWheel: false },
            }}
          />
        </div>
      </Suspense>
    </ClientOnly>
  );
}
