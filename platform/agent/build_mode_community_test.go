//go:build !enterprise

package agent

// isCommunityBuild is true when building without the enterprise tag.
// Used by tests that only apply to community license validation.
const isCommunityBuild = true
