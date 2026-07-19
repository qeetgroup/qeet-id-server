import { cn } from "@qeetrix/ui";
import { type ReactNode, useMemo } from "react";

import { CodeBlock } from "../conversation/code-block";

// A small, safe, dependency-free Markdown renderer for streamed assistant
// output. It parses to React elements (never raw HTML / dangerouslySetInnerHTML),
// so there is no injection surface, and it tolerates a half-finished document —
// an unterminated code fence mid-stream simply renders as an open code block.
// Covers the subset assistants actually emit: headings, bold/italic, inline and
// fenced code, links, ordered/unordered lists, and blockquotes. (Full CommonMark
// + shiki highlighting via react-markdown is a documented follow-up.)

type Block =
  | { kind: "code"; lang?: string; code: string }
  | { kind: "heading"; level: number; text: string }
  | { kind: "ul"; items: string[] }
  | { kind: "ol"; items: string[] }
  | { kind: "quote"; lines: string[] }
  | { kind: "p"; text: string };

const RE = {
  fenceOpen: /^```(\w+)?\s*$/,
  fenceClose: /^```\s*$/,
  heading: /^(#{1,6})\s+(.*)$/,
  ul: /^\s*[-*+]\s+/,
  ol: /^\s*\d+\.\s+/,
  quote: /^\s*>\s?/,
};

function parseBlocks(source: string): Block[] {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const blocks: Block[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line.trim() === "") {
      i++;
      continue;
    }

    const fence = line.match(RE.fenceOpen);
    if (fence) {
      const code: string[] = [];
      i++;
      while (i < lines.length && !RE.fenceClose.test(lines[i])) {
        code.push(lines[i]);
        i++;
      }
      i++; // consume the closing fence (or fall off the end mid-stream)
      blocks.push({ kind: "code", lang: fence[1], code: code.join("\n") });
      continue;
    }

    const heading = line.match(RE.heading);
    if (heading) {
      blocks.push({ kind: "heading", level: heading[1].length, text: heading[2] });
      i++;
      continue;
    }

    if (RE.ul.test(line)) {
      const items: string[] = [];
      while (i < lines.length && RE.ul.test(lines[i])) {
        items.push(lines[i].replace(RE.ul, ""));
        i++;
      }
      blocks.push({ kind: "ul", items });
      continue;
    }

    if (RE.ol.test(line)) {
      const items: string[] = [];
      while (i < lines.length && RE.ol.test(lines[i])) {
        items.push(lines[i].replace(RE.ol, ""));
        i++;
      }
      blocks.push({ kind: "ol", items });
      continue;
    }

    if (RE.quote.test(line)) {
      const quote: string[] = [];
      while (i < lines.length && RE.quote.test(lines[i])) {
        quote.push(lines[i].replace(RE.quote, ""));
        i++;
      }
      blocks.push({ kind: "quote", lines: quote });
      continue;
    }

    const paragraph: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !RE.fenceOpen.test(lines[i]) &&
      !RE.heading.test(lines[i]) &&
      !RE.ul.test(lines[i]) &&
      !RE.ol.test(lines[i]) &&
      !RE.quote.test(lines[i])
    ) {
      paragraph.push(lines[i]);
      i++;
    }
    blocks.push({ kind: "p", text: paragraph.join(" ") });
  }

  return blocks;
}

const INLINE_PATTERNS: { re: RegExp; render: (m: RegExpMatchArray, key: string) => ReactNode }[] = [
  {
    re: /`([^`]+)`/,
    render: (m, key) => (
      <code key={key} className="rounded bg-muted px-1 py-0.5 font-mono text-[0.85em]">
        {m[1]}
      </code>
    ),
  },
  {
    re: /\*\*([^*]+)\*\*/,
    render: (m, key) => <strong key={key}>{renderInline(m[1], key)}</strong>,
  },
  { re: /__([^_]+)__/, render: (m, key) => <strong key={key}>{renderInline(m[1], key)}</strong> },
  { re: /\*([^*]+)\*/, render: (m, key) => <em key={key}>{renderInline(m[1], key)}</em> },
  { re: /_([^_]+)_/, render: (m, key) => <em key={key}>{renderInline(m[1], key)}</em> },
  {
    re: /\[([^\]]+)\]\(([^)\s]+)\)/,
    render: (m, key) => (
      <a
        key={key}
        href={m[2]}
        target="_blank"
        rel="noreferrer noopener"
        className="text-primary underline underline-offset-2"
      >
        {m[1]}
      </a>
    ),
  },
];

function renderInline(text: string, keyPrefix: string): ReactNode[] {
  const out: ReactNode[] = [];
  let rest = text;
  let n = 0;

  while (rest.length > 0) {
    let best: { index: number; length: number; node: ReactNode } | null = null;
    for (const pattern of INLINE_PATTERNS) {
      const m = rest.match(pattern.re);
      if (m && m.index !== undefined && (best === null || m.index < best.index)) {
        best = {
          index: m.index,
          length: m[0].length,
          node: pattern.render(m, `${keyPrefix}-${n}`),
        };
      }
    }
    if (!best) {
      out.push(rest);
      break;
    }
    if (best.index > 0) out.push(rest.slice(0, best.index));
    out.push(best.node);
    rest = rest.slice(best.index + best.length);
    n++;
  }

  return out;
}

const HEADING_CLASS = "font-heading font-semibold text-foreground";

function BlockView({ block, id }: { block: Block; id: string }) {
  switch (block.kind) {
    case "code":
      return <CodeBlock code={block.code} lang={block.lang} />;
    case "heading": {
      const Tag = `h${Math.min(block.level + 2, 6)}` as "h3" | "h4" | "h5" | "h6";
      return (
        <Tag className={cn(HEADING_CLASS, "mt-1 text-sm")}>{renderInline(block.text, id)}</Tag>
      );
    }
    case "ul":
      return (
        <ul className="list-disc space-y-1 ps-5">
          {block.items.map((item, j) => (
            <li key={`${id}-${j}`}>{renderInline(item, `${id}-${j}`)}</li>
          ))}
        </ul>
      );
    case "ol":
      return (
        <ol className="list-decimal space-y-1 ps-5">
          {block.items.map((item, j) => (
            <li key={`${id}-${j}`}>{renderInline(item, `${id}-${j}`)}</li>
          ))}
        </ol>
      );
    case "quote":
      return (
        <blockquote className="border-s-2 ps-3 text-muted-foreground italic">
          {block.lines.map((line, j) => (
            <p key={`${id}-${j}`}>{renderInline(line, `${id}-${j}`)}</p>
          ))}
        </blockquote>
      );
    default:
      return <p className="whitespace-pre-wrap">{renderInline(block.text, id)}</p>;
  }
}

export function MarkdownMessage({ content }: { content: string }) {
  const blocks = useMemo(() => parseBlocks(content), [content]);
  return (
    <div className="flex flex-col gap-2.5 text-sm leading-relaxed text-foreground">
      {blocks.map((block, i) => (
        <BlockView key={`b-${i}`} block={block} id={`b-${i}`} />
      ))}
    </div>
  );
}
