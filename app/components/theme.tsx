import { useSyncExternalStore } from "react";

import { useNonce, useRenderingDocument } from "./document";

const THEME_PREPAINT = `
      try {
        var theme = localStorage.getItem("theme");
        if (theme === "dark" || theme === "light") document.documentElement.setAttribute("data-theme", theme);
      } catch (e) {}
    `;

export function ThemePrepaint() {
  const nonce = useNonce();
  if (!useRenderingDocument()) return null;
  return <script nonce={nonce} suppressHydrationWarning dangerouslySetInnerHTML={{ __html: THEME_PREPAINT }} />;
}

type Theme = "dark" | "light";

const DARK = "(prefers-color-scheme: dark)";
const listeners = new Set<() => void>();

function currentTheme(): Theme {
  const set = document.documentElement.getAttribute("data-theme");
  if (set === "dark" || set === "light") return set;
  return window.matchMedia(DARK).matches ? "dark" : "light";
}

function subscribe(listener: () => void): () => void {
  const media = window.matchMedia(DARK);
  media.addEventListener("change", listener);
  listeners.add(listener);
  return () => {
    media.removeEventListener("change", listener);
    listeners.delete(listener);
  };
}

function toggleTheme(): void {
  const next = currentTheme() === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try {
    localStorage.setItem("theme", next);
  } catch {}
  for (const listener of listeners) listener();
}

export function ThemeToggle() {
  const theme = useSyncExternalStore(subscribe, currentTheme, () => null);
  return (
    <button
      type="button"
      className="theme-toggle"
      aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
      onClick={toggleTheme}
    >
      <svg className="theme-toggle__icon theme-toggle__icon--moon" viewBox="0 0 20 20" aria-hidden="true">
        <path d="M8 2a8 8 0 1 0 10 10A6.5 6.5 0 0 1 8 2z" />
      </svg>
      <svg className="theme-toggle__icon theme-toggle__icon--sun" viewBox="0 0 20 20" aria-hidden="true">
        <path d="M10 6a4 4 0 1 1 0 8 4 4 0 0 1 0-8zM9 0h2v3H9zm0 17h2v3H9zM0 9h3v2H0zm17 0h3v2h-3zM2.5 3.5l1-1 2.8 2.8-1 1zm15 0-1-1-2.8 2.8 1 1zM2.5 16.5l1 1 2.8-2.8-1-1zm15 0-1 1-2.8-2.8 1-1z" />
      </svg>
    </button>
  );
}
