export type NavTreeItem = {
  url: string;
  items?: { url: string }[];
};

/** Leaf destinations are exact so sibling sections never appear active together. */
export function isNavPathActive(pathname: string, url: string): boolean {
  return pathname === url;
}

/** Parent branches stay active for listed children and deeper resource-detail routes. */
export function isNavBranchActive(pathname: string, item: NavTreeItem): boolean {
  if (pathname === item.url) return true;
  return (
    item.items?.some(
      (subItem) =>
        pathname === subItem.url || (subItem.url !== "/" && pathname.startsWith(`${subItem.url}/`)),
    ) ?? false
  );
}
