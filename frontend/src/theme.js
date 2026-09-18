import { useEffect, useState } from "react";

/* ============================================================
   THEME
   The user picks "system", "light" or "dark". "system" follows
   the OS setting and updates live when it changes. The resolved
   theme is written to <html data-theme="..."> for App.css.
   ============================================================ */

const STORAGE_KEY = "mailtrace-theme";

export const THEME_OPTIONS = ["system", "light", "dark"];

const darkQuery = window.matchMedia("(prefers-color-scheme: dark)");

function readPreference() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    return THEME_OPTIONS.includes(saved) ? saved : "system";
  } catch {
    return "system";
  }
}

export default function useTheme() {
  const [preference, setPreference] = useState(readPreference);
  const [systemDark, setSystemDark] = useState(darkQuery.matches);

  useEffect(() => {
    const onChange = (event) => setSystemDark(event.matches);
    darkQuery.addEventListener("change", onChange);
    return () => darkQuery.removeEventListener("change", onChange);
  }, []);

  const resolved =
    preference === "system" ? (systemDark ? "dark" : "light") : preference;

  useEffect(() => {
    document.documentElement.dataset.theme = resolved;
  }, [resolved]);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, preference);
    } catch {
      // Storage unavailable (private mode); the choice lasts this visit only.
    }
  }, [preference]);

  return { preference, resolved, setPreference };
}
