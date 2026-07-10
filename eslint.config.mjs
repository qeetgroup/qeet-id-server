import js from "@eslint/js";
import nextCoreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";
import jsxA11y from "eslint-plugin-jsx-a11y";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import globals from "globals";
import tseslint from "typescript-eslint";

const nextFiles = [
  "apps/website/**/*.{js,jsx,ts,tsx,mjs,cjs}",
  "apps/login/**/*.{js,jsx,ts,tsx,mjs,cjs}",
];

// WCAG 2.2 AA guardrail — jsx-a11y/recommended is enforced (as errors) ONLY on
// the new screens + critical flows below, so repo-wide lint stays green while
// the remaining ~70 screens migrate incrementally. To onboard more screens,
// add their glob to this array (see apps/console/A11Y.md).
// Console isn't a Next app (not in nextFiles), so it needs the jsx-a11y
// plugin registered here. Login IS a Next app: eslint-config-next/core-web-vitals
// already registers its own jsx-a11y plugin instance for nextFiles below —
// re-registering a second instance for the same files throws ESLint flat
// config's "Cannot redefine plugin" error, so loginA11yFiles gets rules only.
const consoleA11yFiles = [
  // Admin — new screens
  "apps/console/src/routes/_app/auth/connections/oidc.tsx",
  "apps/console/src/routes/_app/auth/connections/oidc.$clientId.tsx",
  "apps/console/src/routes/_app/auth/connections/saml-idp.tsx",
  "apps/console/src/routes/_app/auth/api/consent-grants.tsx",
  "apps/console/src/routes/_app/auth/api/signing-keys.tsx",
  "apps/console/src/routes/_app/access/check.tsx",
  "apps/console/src/routes/_app/security/device-authorizations.tsx",
  "apps/console/src/routes/_app/groups.$groupId.tsx",
  // Admin — critical flows + app shell
  "apps/console/src/routes/_app/users/**/*.{ts,tsx}",
  "apps/console/src/routes/_app/auth/login-methods/**/*.{ts,tsx}",
  "apps/console/src/routes/_app.tsx",
  "apps/console/src/features/dashboard/components/app-sidebar.tsx",
  "apps/console/src/features/dashboard/components/nav-main.tsx",
  "apps/console/src/features/dashboard/components/language-switcher.tsx",
];

// Login app (Next.js) — every screen.
const loginA11yFiles = ["apps/login/src/app/**/*.tsx"];

const a11yRules = Object.fromEntries(
  Object.entries(jsxA11y.flatConfigs.recommended.rules).map(([rule, setting]) => {
    const severity = Array.isArray(setting) ? setting[0] : setting;
    const isOff = severity === "off" || severity === 0;
    return [rule, isOff ? setting : "error"];
  }),
);

const forNextApps = (configs) =>
  configs.map((config) => (config.ignores ? config : { ...config, files: nextFiles }));

export default [
  {
    ignores: [
      "**/node_modules/**",
      "**/dist/**",
      "**/build/**",
      "**/.next/**",
      "**/.source/**",
      "**/.turbo/**",
      "**/.output/**",
      "**/.netlify/**",
      "**/coverage/**",
      "**/routeTree.gen.ts",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...forNextApps(nextCoreWebVitals),
  ...forNextApps(nextTypescript),
  {
    files: ["**/*.{js,jsx,ts,tsx,mjs,cjs}"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          argsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
        },
      ],
    },
  },
  {
    // Elevate every rule jsx-a11y/recommended ENABLES to "error" so it gates the
    // target files. Rules recommended deliberately disables (label-has-for is
    // deprecated, etc.) stay off — don't resurrect them.
    files: consoleA11yFiles,
    plugins: jsxA11y.flatConfigs.recommended.plugins,
    languageOptions: jsxA11y.flatConfigs.recommended.languageOptions,
    rules: a11yRules,
  },
  {
    files: loginA11yFiles,
    rules: a11yRules,
  },
];
