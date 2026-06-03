import { ThemeProvider } from "@qeetrix/ui";
import type { Metadata } from "next";

import { I18nProvider } from "@/i18n/provider";
import "./globals.css";

export const metadata: Metadata = {
  title: "Sign in — Qeet ID",
  description: "Sign in to continue.",
  robots: { index: false, follow: false },
};

const STORAGE_KEY = "qeetid-login-theme";

// Set the theme class before first paint to avoid a flash of the wrong theme.
const themeBootstrap = `(function(){try{var t=localStorage.getItem('${STORAGE_KEY}')||'system';var r=t==='system'?(window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'):t;document.documentElement.classList.add(r);}catch(e){}})();`;

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="h-full antialiased" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeBootstrap }} />
      </head>
      <body className="bg-background text-foreground min-h-full font-sans">
        <ThemeProvider defaultTheme="system" storageKey={STORAGE_KEY}>
          <I18nProvider>
            <main className="flex min-h-dvh items-center justify-center p-4">{children}</main>
          </I18nProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
