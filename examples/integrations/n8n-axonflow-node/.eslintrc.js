/**
 * @type {import('@types/eslint').ESLint.ConfigData}
 */
module.exports = {
	parser: '@typescript-eslint/parser',
	parserOptions: {
		project: ['./tsconfig.json'],
		sourceType: 'module',
		extraFileExtensions: ['.json'],
	},
	ignorePatterns: [
		'.eslintrc.js',
		'**/*.js',
		'**/node_modules/**',
		'**/dist/**',
		'scripts/**',
		'test/**',
	],
	overrides: [
		{
			files: ['package.json'],
			parserOptions: {
				project: null,
			},
			plugins: ['eslint-plugin-n8n-nodes-base'],
			extends: ['plugin:n8n-nodes-base/community'],
			rules: {
				'n8n-nodes-base/community-package-json-name-still-default': 'off',
			},
		},
		{
			files: ['./credentials/**/*.ts'],
			plugins: ['eslint-plugin-n8n-nodes-base'],
			extends: ['plugin:n8n-nodes-base/credentials'],
			rules: {
				// The documentationUrl rule misreads HTTP URLs (with dots and
				// hyphens) as camelCase violations and proposes destructive
				// autofixes that break the URL. We hold a valid HTTPS URL
				// (verified by cred-class-field-documentation-url-not-http-url)
				// and silence the false-positive.
				'n8n-nodes-base/cred-class-field-documentation-url-miscased': 'off',
			},
		},
		{
			files: ['./nodes/**/*.ts'],
			plugins: ['eslint-plugin-n8n-nodes-base'],
			extends: ['plugin:n8n-nodes-base/nodes'],
		},
	],
};
