#!/bin/bash
# Publish all BOTCHA packages to npm
# Usage: ./scripts/publish-all.sh [--dry-run]
#
# Authentication:
#   Option 1: Set NPM_TOKEN environment variable
#   Option 2: Create .env file with NPM_TOKEN=npm_xxxx
#   Option 3: Be logged in via 'npm login' (requires OTP/Passkey support)
#
# Get your token: npmjs.com → Account → Access Tokens → Generate (Automation or Granular)

set -e

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load .env file if it exists (supports .env and .env.local)
load_env() {
  local env_file="$1"
  if [ -f "$env_file" ]; then
    echo "📄 Loading $env_file"
    # Export variables, ignoring comments and empty lines
    set -a
    source <(grep -v '^#' "$env_file" | grep -v '^$' | sed 's/^/export /')
    set +a
    return 0
  fi
  return 1
}

# Try loading env files (prefer .env.local over .env)
load_env "$PROJECT_ROOT/.env.local" || load_env "$PROJECT_ROOT/.env" || true

# Parse arguments
DRY_RUN=""
if [ "$1" = "--dry-run" ]; then
  DRY_RUN="--dry-run"
  echo "🔍 DRY RUN MODE - no packages will be published"
  echo ""
fi

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo "📦 BOTCHA Package Publisher"
echo "=========================="
echo ""

# Configure npm auth if NPM_TOKEN is set
if [ -n "$NPM_TOKEN" ]; then
  echo -e "${BLUE}🔑 Using NPM_TOKEN for authentication${NC}"
  npm config set //registry.npmjs.org/:_authToken "$NPM_TOKEN"
  echo ""
fi

# Check npm auth
if ! npm whoami &>/dev/null; then
  echo "❌ Not authenticated with npm."
  echo ""
  echo "Options to authenticate:"
  echo "  1. Set NPM_TOKEN environment variable:"
  echo "     export NPM_TOKEN=npm_xxxxxxxxxxxx"
  echo ""
  echo "  2. Create .env file in project root:"
  echo "     echo 'NPM_TOKEN=npm_xxxxxxxxxxxx' > .env"
  echo ""
  echo "  3. Run 'npm login' (requires OTP if 2FA enabled)"
  echo ""
  echo "Get your token: npmjs.com → Account → Access Tokens → Generate"
  exit 1
fi

echo "✅ Logged in as: $(npm whoami)"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Build everything first
echo "🔨 Building all packages..."
bun run build
echo ""

# Publish root package
echo -e "${BLUE}Publishing @dupecom/botcha...${NC}"
PKG_VERSION=$(node -p "require('./package.json').version")
PUBLISH_OUTPUT=$(npm publish $DRY_RUN --access public 2>&1) && {
  echo -e "${GREEN}✓ @dupecom/botcha@$PKG_VERSION published${NC}"
} || {
  if echo "$PUBLISH_OUTPUT" | grep -qi "cannot publish over the previously published"; then
    echo -e "${YELLOW}⏭ @dupecom/botcha@$PKG_VERSION already published, skipping${NC}"
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
      bun run build 2>/dev/null || true
    fi
    
    PKG_NAME=$(node -p "require('./package.json').name")
    PKG_VERSION=$(node -p "require('./package.json').version")
    
    PUBLISH_OUTPUT=$(npm publish $DRY_RUN --access public 2>&1) && {
      echo -e "${GREEN}✓ $PKG_NAME@$PKG_VERSION published${NC}"
    } || {
      if echo "$PUBLISH_OUTPUT" | grep -qi "cannot publish over the previously published"; then
        echo -e "${YELLOW}⏭ $PKG_NAME@$PKG_VERSION already published, skipping${NC}"
      else
        echo "$PUBLISH_OUTPUT"
        echo "❌ Failed to publish $PKG_NAME"
        cd "$PROJECT_ROOT"
        exit 1
      fi
    }
    cd "$PROJECT_ROOT"
    echo ""
  fi
done

echo "=========================="
echo "🎉 All packages published!"
