// ESLint flat config (TypeScript + React).
//
// The project compiles with TypeScript 7 (native compiler), which ships no
// JavaScript compiler API. typescript-eslint still needs the TS 6 API, so we
// install it as `@typescript/typescript6` and point every `import "typescript"`
// made while linting at that package. This only affects the ESLint process;
// `tsc -b` / `vite build` keep using TypeScript 7.
import { registerHooks } from "node:module";

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "typescript") return nextResolve("@typescript/typescript6", context);
    return nextResolve(specifier, context);
  },
});

const { default: js } = await import("@eslint/js");
const { default: globals } = await import("globals");
const { default: reactHooks } = await import("eslint-plugin-react-hooks");
const { default: reactRefresh } = await import("eslint-plugin-react-refresh");
const { default: tseslint } = await import("typescript-eslint");

export default tseslint.config(
  { ignores: ["dist", "node_modules"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: { ecmaVersion: 2022, globals: globals.browser },
    plugins: { "react-hooks": reactHooks, "react-refresh": reactRefresh },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
    },
  },
);
