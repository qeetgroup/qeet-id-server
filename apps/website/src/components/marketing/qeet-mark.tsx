import { cn } from "@qeetrix/ui";
import { QeetLogoOnDark, QeetLogoOnLight } from "@qeetrix/ui/brand";

type QeetMarkProps = {
  /** Pixel size of the square mark. */
  size?: number;
  className?: string;
};

// Theme-aware Qeet mark: the dark artwork on light surfaces, the light
// artwork on dark surfaces. The variant toggle uses `dark:` utilities written
// here (in app source) so the app's Tailwind build actually emits them —
// QeetLogo's built-in "auto" mode relies on classes inside the package that
// the consumer's Tailwind never scans.
export function QeetMark({ size = 28, className }: QeetMarkProps) {
  return (
    <>
      <QeetLogoOnLight size={size} className={cn("block dark:hidden", className)} />
      <QeetLogoOnDark size={size} className={cn("hidden dark:block", className)} />
    </>
  );
}
