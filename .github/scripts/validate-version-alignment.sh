#!/usr/bin/env bash
# Validates that version defaults across the repo match the latest CHANGELOG version.
# Run locally: ./scripts/validate-version-alignment.sh
# CI: runs on every push that touches CHANGELOG.md, docker-compose*.yml, Dockerfile*, or capabilities.go

set -euo pipefail

ERRORS=0

# Extract latest *released* version from CHANGELOG.md (first ## [x.y.z] line that
# isn't the Keep-a-Changelog "Unreleased" placeholder). The Unreleased section
# accumulates in-flight changes between tags and must not be used as the
# expected-version target — version defaults across the repo only get bumped
# when we actually cut a tag.
LATEST_VERSION=$(grep -m1 -E '^## \[[0-9]' CHANGELOG.md | sed 's/## \[\(.*\)\].*/\1/')

if [ -z "$LATEST_VERSION" ]; then
    echo "❌ Could not extract version from CHANGELOG.md"
    exit 1
fi

echo "📋 Latest CHANGELOG version: $LATEST_VERSION"
echo ""

# Check docker-compose*.yml AXONFLOW_VERSION defaults
echo "🐳 Checking docker-compose version defaults..."
while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    lineno=$(echo "$line" | cut -d: -f2)
    default=$(echo "$line" | grep -o ':-[0-9.]*' | sed 's/:-//')

    if [ "$default" != "$LATEST_VERSION" ]; then
        echo "  ❌ $file:$lineno — AXONFLOW_VERSION default is $default, expected $LATEST_VERSION"
        ERRORS=$((ERRORS + 1))
    else
        echo "  ✅ $file:$lineno — $default"
    fi
done < <(grep -rn 'AXONFLOW_VERSION.*:-[0-9]' docker-compose*.yml 2>/dev/null || true)

echo ""

# Check Dockerfile ARG AXONFLOW_VERSION defaults
echo "📦 Checking Dockerfile version defaults..."
while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    lineno=$(echo "$line" | cut -d: -f2)
    default=$(echo "$line" | grep -o '=[0-9.]*' | sed 's/=//')

    if [ "$default" != "$LATEST_VERSION" ]; then
        echo "  ❌ $file:$lineno — ARG AXONFLOW_VERSION default is $default, expected $LATEST_VERSION"
        ERRORS=$((ERRORS + 1))
    else
        echo "  ✅ $file:$lineno — $default"
    fi
done < <(grep -rn '^ARG AXONFLOW_VERSION=[0-9]' platform/ ee/ --include="Dockerfile*" 2>/dev/null || true)

echo ""

# Check capabilities.go platform version constants
echo "🔧 Checking capabilities.go platform version..."
while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    lineno=$(echo "$line" | cut -d: -f2)
    version=$(echo "$line" | grep -o '"[0-9.]*"' | tr -d '"')

    if [ "$version" != "$LATEST_VERSION" ]; then
        echo "  ❌ $file:$lineno — platform version is $version, expected $LATEST_VERSION"
        ERRORS=$((ERRORS + 1))
    else
        echo "  ✅ $file:$lineno — $version"
    fi
done < <(grep -rn 'PlatformVersion.*=.*"[0-9]' platform/ ee/ --include="*.go" 2>/dev/null || true)

echo ""

# Summary
if [ "$ERRORS" -gt 0 ]; then
    echo "❌ Found $ERRORS version misalignment(s). Update the stale defaults to match CHANGELOG v$LATEST_VERSION."
    exit 1
else
    echo "✅ All version references are aligned with v$LATEST_VERSION"
fi
