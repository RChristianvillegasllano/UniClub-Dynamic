/**
 * Security-focused ESLint configuration
 * Catches common security vulnerabilities in code
 */

module.exports = {
  extends: ['eslint:recommended'],
  env: {
    node: true,
    es2022: true
  },
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module'
  },
  rules: {
    // Security-related rules
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-new-func': 'error',
    'no-script-url': 'error',
    'no-proto': 'error',
    'no-iterator': 'error',
    'no-caller': 'error',
    'no-extend-native': 'error',
    
    // Prevent dangerous patterns
    'no-console': 'warn',
    'no-debugger': 'error',
    'no-alert': 'error',
    
    // SQL Injection prevention
    'no-template-curly-in-string': 'error',
    
    // XSS prevention
    'no-unescaped-entities': 'error',
    
    // Best practices
    'eqeqeq': ['error', 'always'],
    'no-var': 'error',
    'prefer-const': 'error',
    'no-unused-vars': ['error', { 
      argsIgnorePattern: '^_',
      varsIgnorePattern: '^_'
    }],
    
    // Prevent prototype pollution
    'no-prototype-builtins': 'error',
    
    // Prevent dangerous regex
    'no-control-regex': 'error',
    'no-regex-spaces': 'error',
    
    // Prevent dangerous string methods
    'no-implied-eval': 'error',
    
    // Require error handling
    'handle-callback-err': 'error',
    'no-throw-literal': 'error'
  },
  overrides: [
    {
      files: ['**/*.test.js', '**/*.spec.js'],
      env: {
        jest: true,
        mocha: true
      },
      rules: {
        'no-console': 'off'
      }
    }
  ]
};

