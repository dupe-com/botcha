#!/bin/bash
# Publish all BOTCHA packages to npm
# Usage: ./scripts/publish-all.sh [--dry-run]

set -e

DRY_RUN=""
if [ "$1" = "--dry-run" ]; then
  DRY_RUN="--dry-run"
  echo "🔍 DRY RUN MODE - no packages will be published"
  echo ""
fi

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "📦 BOTCHA Package Publisher"
echo "=========================="
echo ""

# Check npm auth
if ! npm whoami &>/dev/null; then
  echo "❌ Not logged into npm. Run 'npm login' first."
  exit 1
fi

echo "✅ Logged in as: $(npm whoami)"
echo ""

# Build everything first
echo "🔨 Building all packages..."
npm run build
echo ""

# Publish root package
echo -e "${BLUE}Publishing @dupecom/botcha...${NC}"
PKG_VERSION=$(node -p "require('./package.json').version")
PUBLISH_OUTPUT=$(npm publish $DRY_RUN --access public 2>&1) && {
  echo -e "${GREEN}✓ @dupecom/botcha published${NC}"
} || {
  if echo "$PUBLISH_OUTPUT" | grep -q "cannot publish over the previously published"; then
    echo -e "${BLUE}⏭ @dupecom/botcha@$PKG_VERSION already published, skipping${NC}"
  else
    echo "$PUBLISH_OUTPUT"
    echo "❌ Failed to publish @dupecom/botcha"
    exit 1
  fi
}
echo ""

# Publish sub-packages
PACKAGES=("cli" "cloudflare-workers" "langchain")

for pkg in "${PACKAGES[@]}"; do
  PKG_PATH="packages/$pkg"
  if [ -d "$PKG_PATH" ]; then
    echo -e "${BLUE}Publishing @dupecom/botcha-$pkg...${NC}"
    cd "$PKG_PATH"
    
    # Build if there's a build script
    if grep -q '"build"' package.json; then
      npm run build 2>/dev/null || true
    fi
    
    PKG_NAME=$(node -p "require('./package.json').name")
    PKG_VERSION=$(node -p "require('./package.json').version")
    
    PUBLISH_OUTPUT=$(npm publish $DRY_RUN --access public 2>&1) && {
      echo -e "${GREEN}✓ $PKG_NAME published${NC}"
    } || {
      if echo "$PUBLISH_OUTPUT" | grep -qi "cannot publish over the previously published"; then
        echo -e "${BLUE}⏭ $PKG_NAME@$PKG_VERSION already published, skipping${NC}"
      else
        echo "$PUBLISH_OUTPUT"
        echo "❌ Failed to publish $PKG_NAME"
        cd - > /dev/null
        exit 1
      fi
    }
    cd - > /dev/null
    echo ""
  fi
done

echo "=========================="
echo "🎉 All packages published!"
