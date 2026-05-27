import type { Preview } from "@storybook/react";

import "../src/index.css";

/**
 * Preview config: pulls in the shared Tailwind layer + base-ui styles
 * via index.css so stories render with the same look-and-feel as the
 * real apps. The light/dark theme decorator follows the `class` strategy
 * used by ThemeProvider in production.
 */
const preview: Preview = {
  parameters: {
    controls: { expanded: true },
    backgrounds: { disable: true }, // we drive bg via theme, not by Storybook
    actions: { argTypesRegex: "^on[A-Z].*" },
  },
  globalTypes: {
    theme: {
      name: "Theme",
      description: "Light / dark mode",
      defaultValue: "light",
      toolbar: {
        icon: "circlehollow",
        items: [
          { value: "light", title: "Light" },
          { value: "dark", title: "Dark" },
        ],
      },
    },
  },
  decorators: [
    (Story, ctx) => {
      const theme = (ctx.globals as { theme?: string }).theme ?? "light";
      if (typeof document !== "undefined") {
        document.documentElement.classList.toggle("dark", theme === "dark");
      }
      return Story();
    },
  ],
};

export default preview;
