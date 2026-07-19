import { SparklesIcon } from "lucide-react";

// Starter prompts shown on an empty conversation. These are generic defaults;
// the suggestions feature replaces them with route-aware actions derived from
// the current ConsoleContext.
const STARTER_PROMPTS = [
  "Show users who signed in from a new device this week",
  "Draft a least-privilege role for support engineers",
  "Simulate whether alice@acme.com can delete billing settings",
  "Generate Terraform for our production OIDC client",
];

export function ConversationEmptyState({ onPick }: { onPick: (prompt: string) => void }) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center px-6 py-10 text-center">
      <span
        className="grid size-12 place-items-center rounded-2xl bg-primary/10 text-primary ring-1 ring-primary/15"
        aria-hidden
      >
        <SparklesIcon className="size-6" />
      </span>
      <h2 className="mt-4 font-heading text-base font-semibold">How can I help?</h2>
      <p className="mt-1 max-w-sm text-sm text-muted-foreground">
        Ask about your tenant, run administrative actions as tools, or generate code — all under
        your own permissions.
      </p>
      <ul className="mt-6 flex w-full max-w-md flex-col gap-2">
        {STARTER_PROMPTS.map((prompt) => (
          <li key={prompt}>
            <button
              type="button"
              onClick={() => onPick(prompt)}
              className="w-full rounded-lg border bg-card/40 px-3 py-2.5 text-start text-sm text-foreground transition-colors hover:border-primary/40 hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              {prompt}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
