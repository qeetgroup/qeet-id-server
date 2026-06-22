import { ThemeProvider } from "@qeetrix/ui";
import type { Metadata } from "next";
import { Fira_Code } from "next/font/google";
import {
  OrganizationJsonLd,
  WebSiteJsonLd,
} from "@/components/marketing/structured-data";
import "./globals.css";

const firaCode = Fira_Code({
  subsets: ["latin"],
  variable: "--font-fira-code",
  display: "swap",
});

export const metadata: Metadata = {
  title: {
    default: "Qeet ID — One Identity. Every Platform.",
    template: "%s | Qeet ID",
  },
  description:
    "Qeet ID is the identity platform for modern teams. SSO, MFA, passkeys, RBAC, and session management — built for developers, trusted by enterprises.",
  metadataBase: new URL("https://qeetid.com"),
  alternates: {
    canonical: "/",
  },
  icons: {
    // Theme-adaptive favicon: dark artwork on light UI, light artwork on dark
    // UI. The .ico is the universal fallback for browsers without SVG support.
    icon: [
      {
        url: "/qeet-logo-on-light.svg",
        type: "image/svg+xml",
        media: "(prefers-color-scheme: light)",
      },
      {
        url: "/qeet-logo-on-dark.svg",
        type: "image/svg+xml",
        media: "(prefers-color-scheme: dark)",
      },
      { url: "/favicon.ico", sizes: "48x48" },
    ],
    shortcut: ["/favicon.ico"],
    apple: [{ url: "/apple-icon.png", type: "image/png", sizes: "180x180" }],
  },
  openGraph: {
    title: "Qeet ID — One Identity. Every Platform.",
    description:
      "SSO, MFA, passkeys, RBAC, and session management — built for developers, trusted by enterprises.",
    type: "website",
    siteName: "Qeet ID",
    locale: "en_US",
    url: "https://qeetid.com",
  },
  twitter: {
    card: "summary_large_image",
    title: "Qeet ID — One Identity. Every Platform.",
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
  authors: [{ name: "Qeet ID", url: "https://qeetid.com" }],
  creator: "Qeet ID",
  publisher: "Qeet ID",
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
        {/* Site-wide publisher + website schema. Emitted once in the root
            layout so it covers every route (marketing + any future surface). */}
        <OrganizationJsonLd />
        <WebSiteJsonLd />
        <ThemeProvider defaultTheme="system" storageKey={STORAGE_KEY}>
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
