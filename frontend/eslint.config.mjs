import js from "@eslint/js";
import nextCoreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";
import jsxA11y from "eslint-plugin-jsx-a11y";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import globals from "globals";
import tseslint from "typescript-eslint";

const nextFiles = [
  "apps/qeetid-web/**/*.{js,jsx,ts,tsx,mjs,cjs}",
  "apps/qeetid-login/**/*.{js,jsx,ts,tsx,mjs,cjs}",
];

// WCAG 2.2 AA guardrail — jsx-a11y/recommended is enforced (as errors) ONLY on
// the new screens + critical flows below, so repo-wide lint stays green while
// the remaining ~70 screens migrate incrementally. To onboard more screens,
// add their glob to this array (see apps/qeetid-admin/A11Y.md).
const a11yFiles = [
  // Admin — new screens
  "apps/qeetid-admin/src/routes/_app/auth/connections/oidc.tsx",
  "apps/qeetid-admin/src/routes/_app/auth/connections/oidc.$clientId.tsx",
  "apps/qeetid-admin/src/routes/_app/auth/connections/saml-idp.tsx",
  "apps/qeetid-admin/src/routes/_app/auth/api/consent-grants.tsx",
  "apps/qeetid-admin/src/routes/_app/auth/api/signing-keys.tsx",
  "apps/qeetid-admin/src/routes/_app/access/check.tsx",
  "apps/qeetid-admin/src/routes/_app/security/device-authorizations.tsx",
  "apps/qeetid-admin/src/routes/_app/groups.$groupId.tsx",
  // Admin — critical flows + app shell
  "apps/qeetid-admin/src/routes/_app/users/**/*.{ts,tsx}",
  "apps/qeetid-admin/src/routes/_app/auth/login-methods/**/*.{ts,tsx}",
  "apps/qeetid-admin/src/routes/_app.tsx",
  "apps/qeetid-admin/src/features/dashboard/components/app-sidebar.tsx",
  "apps/qeetid-admin/src/features/dashboard/components/nav-main.tsx",
  "apps/qeetid-admin/src/features/dashboard/components/language-switcher.tsx",
  // Login app (Next.js) — every screen
  "apps/qeetid-login/src/app/**/*.tsx",
];

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
    files: a11yFiles,
    plugins: jsxA11y.flatConfigs.recommended.plugins,
    languageOptions: jsxA11y.flatConfigs.recommended.languageOptions,
    // Elevate every rule jsx-a11y/recommended ENABLES to "error" so it gates the
    // target files. Rules recommended deliberately disables (label-has-for is
    // deprecated, etc.) stay off — don't resurrect them.
    rules: Object.fromEntries(
      Object.entries(jsxA11y.flatConfigs.recommended.rules).map(([rule, setting]) => {
        const severity = Array.isArray(setting) ? setting[0] : setting;
        const isOff = severity === "off" || severity === 0;
        return [rule, isOff ? setting : "error"];
      }),
    ),
  },
];
