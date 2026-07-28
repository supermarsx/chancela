import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import prettier from 'eslint-config-prettier';

// ESLint 9 flat config. Prettier config comes last so it disables any stylistic
// rules that would fight the formatter.
export default tseslint.config(
  { ignores: ['dist', 'node_modules', 'coverage'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    plugins: { 'react-hooks': reactHooks },
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
    },
    rules: {
      // TypeScript resolves identifiers itself; core no-undef only produces
      // false positives on DOM/globals here.
      'no-undef': 'off',
      // A leading underscore is this codebase's existing signal for "bound on
      // purpose, read nowhere" — a destructure that omits a key, or a mock typed
      // with the real signature so a later assertion can read the argument list.
      // Without this the convention was aspirational and the rule fired on it.
      // Accidental unused bindings are unaffected: they are not underscore-named.
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
          ignoreRestSiblings: true,
        },
      ],
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
    },
  },
  prettier,
);
