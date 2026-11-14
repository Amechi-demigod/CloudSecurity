import { Lock } from "lucide-react";
import type { ReactNode } from "react";
import type { ModuleKey } from "../api";
import { CONTACT_URL, MODULES, useModules } from "../lib/modules";
import { Card, Empty } from "./ui";

/** "Contact Sentrigis": opens the website's contact section in a new tab. */
export function ContactLink() {
  return (
    <a
      href={CONTACT_URL}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-block rounded bg-accent px-3 py-1.5 text-sm font-medium text-white transition hover:brightness-110 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
    >
      Contact Sentrigis
    </a>
  );
}

/** Page-sized empty state for a module the organisation does not have. */
export function ModuleLocked({ module }: { module: ModuleKey }) {
  const m = MODULES[module];
  return (
    <div className="mx-auto mt-10 max-w-xl rounded-lg border border-line bg-surface-1">
      <Empty icon={Lock} title={`${m.label} isn't part of your subscription`} action={<ContactLink />}>
        {m.description}
      </Empty>
    </div>
  );
}

/** Small locked card for a section of an always-on page (Connectors & scans). */
export function LockedCard({ module, className = "" }: { module: ModuleKey; className?: string }) {
  const m = MODULES[module];
  return (
    <Card className={className}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex min-w-0 items-start gap-3">
          <Lock aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-ink-3" />
          <div>
            <h3 className="text-sm font-semibold text-ink">{m.label} isn&apos;t part of your subscription</h3>
            <p className="mt-0.5 text-sm text-ink-3">{m.description}</p>
          </div>
        </div>
        <ContactLink />
      </div>
    </Card>
  );
}

/** Renders the page when the organisation has (any of) the module(s), else the locked state. */
export function RequireModule({ module, children }: { module: ModuleKey | ModuleKey[]; children: ReactNode }) {
  const { has } = useModules();
  const keys = Array.isArray(module) ? module : [module];
  return has(...keys) ? <>{children}</> : <ModuleLocked module={keys[0]} />;
}
