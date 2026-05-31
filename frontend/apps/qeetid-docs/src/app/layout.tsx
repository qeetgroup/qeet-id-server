import { RootProvider } from "fumadocs-ui/provider/next";
import { Fira_Code } from "next/font/google";
import "./global.css";

/**
 * Fira Code is loaded from Google because @qeetrix/ui mis-defines `--font-mono`
 * as 'Cal Sans Text' (not a real monospace). This variable wins over the package
 * default in global.css.
 */
const firaCode = Fira_Code({
  subsets: ["latin"],
  variable: "--font-fira-code",
  display: "swap",
});

export default function Layout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={firaCode.variable} suppressHydrationWarning>
      <body className="flex flex-col min-h-screen">
        <RootProvider>{children}</RootProvider>
      </body>
    </html>
  );
}
