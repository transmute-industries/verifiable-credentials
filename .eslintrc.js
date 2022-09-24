module.exports = {
  env: {
    browser: true,
    commonjs: true,
    es2021: true,
  },
  extends: 'google',
  overrides: [],
  parserOptions: {
    ecmaVersion: 'latest',
  },
  rules: {
    'camelcase': [0],
    'require-jsdoc': [0],
    'no-unused-vars': [0],
  },
};
