import { ThemeProvider } from "@qeetid/ui";
import type { Metadata } from "next";
import { Fira_Code } from "next/font/google";
import "./globals.css";

const firaCode = Fira_Code({
  subsets: ["latin"],
  variable: "--font-fira-code",
  display: "swap",
});

export const metadata: Metadata = {
  title: {
    default: "Qeetid — One Identity. Every Platform.",
    template: "%s | Qeetid",
  },
  description:
    "Qeetid is the identity platform for modern teams. SSO, MFA, passkeys, RBAC, and session management — built for developers, trusted by enterprises.",
  metadataBase: new URL("https://qeetid.com"),
  alternates: {
    canonical: "/",
  },
  openGraph: {
    title: "Qeetid — One Identity. Every Platform.",
    description:
      "SSO, MFA, passkeys, RBAC, and session management — built for developers, trusted by enterprises.",
    type: "website",
    siteName: "Qeetid",
    locale: "en_US",
    url: "https://qeetid.com",
  },
  twitter: {
    card: "summary_large_image",
    title: "Qeetid — One Identity. Every Platform.",
    description:
      "SSO, MFA, passkeys, RBAC, and session management — built for developers, trusted by enterprises.",
    site: "@qeetid",
    creator: "@qeetid",
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-snippet": -1,
      "max-image-preview": "large",
      "max-video-preview": -1,
    },
  },
  keywords: [
    "identity platform",
    "SSO",
    "single sign-on",
    "MFA",
    "passkeys",
    "RBAC",
    "auth0 alternative",
    "open source identity",
    "self-hosted auth",
  ],
  authors: [{ name: "Qeetid", url: "https://qeetid.com" }],
  creator: "Qeetid",
  publisher: "Qeetid",
};

const STORAGE_KEY = "qeetid-web-theme";

const themeBootstrap = `(function(){try{var t=localStorage.getItem('${STORAGE_KEY}')||'system';var r=t==='system'?(window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'):t;document.documentElement.classList.add(r);}catch(e){}})();`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`h-full antialiased ${firaCode.variable}`} suppressHydrationWarning>
      <head>
        {/* Set theme class before first paint to avoid FOUC. */}
        <script dangerouslySetInnerHTML={{ __html: themeBootstrap }} />
      </head>
      <body className="font-sans">
        <ThemeProvider defaultTheme="system" storageKey={STORAGE_KEY}>
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
