import { Globe, Laptop, ShieldCheck, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { useBrand } from "../lib/brand";

const POINTS: { icon: LucideIcon; title: string; text: string }[] = [
  { icon: Globe, title: "Cloud posture and exposure", text: "Azure, AWS and GCP misconfigurations, internet exposure and attack paths in one view." },
  { icon: ShieldCheck, title: "Risk you can act on", text: "Vulnerabilities ranked by runtime use, exposure and known exploits, not by count." },
  { icon: Laptop, title: "Endpoints included", text: "Windows and macOS posture, IT assets and audited remote actions for lost devices." },
];

/**
 * Sign-in and invitation pages: the product story on the left (wide screens only) and the form
 * card on the right. The brand comes from the server (BRAND_NAME / BRAND_TAGLINE).
 */
export function AuthLayout({ children, footer }: { children: ReactNode; footer?: ReactNode }) {
  const brand = useBrand();
  return (
    <div className="grid min-h-full bg-surface-0 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
      <aside className="relative hidden overflow-hidden border-r border-line bg-surface-1 lg:flex lg:flex-col lg:justify-between lg:p-12">
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 opacity-[0.35]"
          style={{
            backgroundImage:
              "linear-gradient(var(--color-line) 1px, transparent 1px), linear-gradient(90deg, var(--color-line) 1px, transparent 1px)",
            backgroundSize: "48px 48px",
            maskImage: "radial-gradient(ellipse at 30% 40%, black 10%, transparent 65%)",
            WebkitMaskImage: "radial-gradient(ellipse at 30% 40%, black 10%, transparent 65%)",
          }}
        />
        <div aria-hidden className="pointer-events-none absolute -left-16 top-1/4 h-80 w-80 rounded-full bg-accent/20 blur-3xl" />
        <div className="relative flex items-center gap-3">
          <span className="flex h-11 w-11 items-center justify-center rounded-xl border border-line bg-surface-0 shadow-lg">
            <img src="/shield.svg" alt="" className="h-6 w-6" />
          </span>
          <div>
            <div className="text-lg font-bold tracking-tight text-ink">{brand.name}</div>
            <div className="text-sm text-ink-3">{brand.tagline}</div>
          </div>
        </div>
        <div className="relative max-w-md">
          <p className="text-3xl font-bold leading-tight tracking-tight text-ink">
            See what is exposed, what is exploitable, and fix that first.
          </p>
          <ul className="mt-8 space-y-5">
            {POINTS.map((p) => (
              <li key={p.title} className="flex gap-3">
                <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-accent/15 text-accent">
                  <p.icon aria-hidden className="h-5 w-5" />
                </span>
                <div>
                  <div className="text-sm font-semibold text-ink">{p.title}</div>
                  <div className="text-sm text-ink-2">{p.text}</div>
                </div>
              </li>
            ))}
          </ul>
        </div>
        <p className="relative text-xs text-ink-3">© {new Date().getFullYear()} {brand.name}</p>
      </aside>

      <div className="flex items-center justify-center px-4 py-10 sm:px-8">
        <main className="w-full max-w-sm">
          <div className="mb-6 flex flex-col items-center text-center lg:sr-only">
            <span className="mb-3 flex h-12 w-12 items-center justify-center rounded-xl border border-line bg-surface-1 shadow-lg">
              <img src="/shield.svg" alt="" className="h-7 w-7" />
            </span>
            <h1 className="text-xl font-semibold text-ink">{brand.name}</h1>
            <p className="mt-1 text-sm text-ink-3">{brand.tagline}</p>
          </div>
          <div className="rounded-2xl border border-line bg-surface-1 p-6 shadow-xl shadow-black/10 sm:p-7">{children}</div>
          {footer && <div className="mt-6 text-center text-xs text-ink-3">{footer}</div>}
        </main>
      </div>
    </div>
  );
}
