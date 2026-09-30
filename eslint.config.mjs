const globals = Object.fromEntries(['process', 'Buffer', 'console', 'URL', 'TextDecoder', 'TextEncoder',
  'fetch', 'Response', 'AbortSignal', 'performance', 'structuredClone', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'].map(name => [name, 'readonly']));

export default [{
  files: ['src/**/*.mjs', 'scripts/**/*.mjs', 'tests/**/*.mjs'],
  languageOptions: { ecmaVersion: 'latest', sourceType: 'module', globals },
  rules: {
    'no-undef': 'error', 'no-unreachable': 'error', 'no-dupe-keys': 'error',
    'no-constant-condition': ['error', { checkLoops: false }],
    'no-async-promise-executor': 'error', 'no-promise-executor-return': 'error',
    'no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none', ignoreRestSiblings: true }],
  },
}];
