import type { StorybookConfig } from "@storybook/react-vite";

/**
 * Storybook scaffold for @qeetid/ui.
 *
 * To enable locally:
 *   pnpm --filter @qeetid/ui add -D storybook @storybook/react-vite @storybook/test
 *
 * Then `pnpm --filter @qeetid/ui storybook` runs on :6006. Sample stories
 * live in `src/stories/*.stories.tsx` — copy `button.stories.tsx` to
 * cover a new primitive.
 *
 * CI step for Chromatic visual regression is out of scope here; see
 * IMPROVEMENTS §13.7.
 */
const config: StorybookConfig = {
  stories: ["../src/stories/**/*.stories.@(ts|tsx|mdx)"],
  addons: [
    "@storybook/addon-essentials",
    "@storybook/addon-themes",
    "@storybook/addon-a11y",
  ],
  framework: {
    name: "@storybook/react-vite",
    options: {},
  },
  typescript: {
    reactDocgen: "react-docgen-typescript",
  },
};

export default config;
