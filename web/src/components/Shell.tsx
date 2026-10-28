import type { ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import { StatusRail } from "./StatusRail";

export function Shell({ children }: { children: ReactNode }) {
  const location = useLocation();
  const onLaunch = location.pathname === "/";

  return (
    <div className="relative min-h-screen bg-ink text-paper">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,_rgba(232,184,109,0.07),_transparent_52%)]" />
      <header className="relative z-10 border-b border-line">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-6 px-6 py-4">
          <Link to="/" className="group flex items-baseline gap-3">
            <span className="stamp text-amber">OSINT Hub</span>
            <span className="hidden text-xs text-muted sm:inline">Investigation Console</span>
          </Link>
          <div className="flex items-center gap-4">
            <StatusRail compact />
            {!onLaunch && (
              <Link
                to="/"
                className="stamp text-muted hover:text-paper transition-colors"
              >
                New dossier
              </Link>
            )}
          </div>
        </div>
      </header>
      <main className="relative z-10 mx-auto w-full max-w-6xl px-6 py-8">{children}</main>
    </div>
  );
}
