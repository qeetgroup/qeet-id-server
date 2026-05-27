/**
 * <Sandbox /> embeds a hosted code sandbox (StackBlitz or CodeSandbox)
 * directly in the docs so readers can "Run this code" without leaving
 * the page. Falls back to a clear-text link if the iframe is blocked
 * (CSP, privacy extensions) so the docs always work.
 *
 * Usage in MDX:
 *
 *   <Sandbox
 *     provider="stackblitz"
 *     id="github/qeetgroup/examples/tree/main/nextjs-quickstart"
 *     title="Next.js quickstart"
 *   />
 */

export interface SandboxProps {
  provider: "stackblitz" | "codesandbox";
  /**
   * Provider-specific id. For StackBlitz this is the project slug or a
   * `github/{owner}/{repo}/tree/{ref}/{path}` triple. For CodeSandbox
   * it's the sandbox id (the bit after `/s/`).
   */
  id: string;
  /** Display title shown in the iframe header + alt text. */
  title: string;
  /** Iframe height in pixels. Defaults to 480 — tall enough for a real editor. */
  height?: number;
  /**
   * Initial file to focus in the editor. StackBlitz only. Defaults to
   * the project's entry file (provider chooses).
   */
  file?: string;
  /** Hide the editor (preview-only). Defaults to false. */
  previewOnly?: boolean;
}

function buildEmbedURL(props: SandboxProps): string {
  if (props.provider === "stackblitz") {
    const params = new URLSearchParams({
      embed: "1",
      view: props.previewOnly ? "preview" : "editor",
      hideExplorer: "0",
      hideNavigation: "0",
      theme: "dark",
    });
    if (props.file) params.set("file", props.file);
    // The id may be a slug ("vitejs-vite-xxx") or a github path. The
    // github path uses a different base URL.
    const base = props.id.startsWith("github/")
      ? `https://stackblitz.com/${props.id}`
      : `https://stackblitz.com/edit/${props.id}`;
    return `${base}?${params.toString()}`;
  }
  // codesandbox
  const params = new URLSearchParams({
    view: props.previewOnly ? "preview" : "split",
    theme: "dark",
    hidenavigation: "1",
  });
  return `https://codesandbox.io/embed/${props.id}?${params.toString()}`;
}

function externalURL(props: SandboxProps): string {
  if (props.provider === "stackblitz") {
    return props.id.startsWith("github/")
      ? `https://stackblitz.com/${props.id}`
      : `https://stackblitz.com/edit/${props.id}`;
  }
  return `https://codesandbox.io/s/${props.id}`;
}

export function Sandbox(props: SandboxProps) {
  const { title, height = 480 } = props;
  const src = buildEmbedURL(props);
  const fallback = externalURL(props);

  return (
    <div className="my-6 overflow-hidden rounded-lg border bg-card">
      <div className="flex items-center justify-between border-b bg-muted/40 px-3 py-2 text-xs">
        <div className="flex items-center gap-2">
          <span className="font-mono text-muted-foreground">
            {props.provider === "stackblitz" ? "StackBlitz" : "CodeSandbox"}
          </span>
          <span className="truncate font-medium">{title}</span>
        </div>
        <a
          href={fallback}
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary underline-offset-2 hover:underline"
        >
          Open in new tab ↗
        </a>
      </div>
      <iframe
        src={src}
        title={title}
        height={height}
        // sandbox is intentionally permissive — code sandboxes need
        // network + scripts to run user code. allow-same-origin is
        // required by both providers so they can talk to their CDN.
        sandbox="allow-forms allow-modals allow-popups allow-presentation allow-same-origin allow-scripts"
        allow="accelerometer; camera; encrypted-media; geolocation; gyroscope; hid; microphone; midi; payment; usb; xr-spatial-tracking"
        loading="lazy"
        className="block w-full border-0"
        style={{ height, colorScheme: "dark" }}
      />
    </div>
  );
}
