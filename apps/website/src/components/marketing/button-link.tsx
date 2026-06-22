import { Button } from "@qeetrix/ui";
import Link from "next/link";
import type { ComponentProps } from "react";

type LinkProps = ComponentProps<typeof Link>;
type ButtonProps = ComponentProps<typeof Button>;

type ButtonLinkProps = Omit<ButtonProps, "render" | "nativeButton"> &
  Pick<LinkProps, "href" | "prefetch" | "replace" | "scroll" | "target" | "rel">;

export function ButtonLink({
  href,
  prefetch,
  replace,
  scroll,
  target,
  rel,
  children,
  ...buttonProps
}: ButtonLinkProps) {
  return (
    <Button
      {...buttonProps}
      nativeButton={false}
      render={
        <Link
          href={href}
          prefetch={prefetch}
          replace={replace}
          scroll={scroll}
          target={target}
          rel={rel}
        />
      }
    >
      {children}
    </Button>
  );
}
