#!/bin/bash
# Setup BOTCHA labels for the repository
# Run this once: ./.github/setup-labels.sh

REPO="dupe-com/botcha"

# Create botcha-pending label (yellow)
gh label create "botcha-pending" \
  --repo "$REPO" \
  --description "PR awaiting BOTCHA agent verification" \
  --color "FEF3C7" \
  --force

# Create botcha-verified label (green)
gh label create "botcha-verified" \
  --repo "$REPO" \
  --description "✅ Contributor verified as AI agent" \
  --color "D1FAE5" \
  --force

# Create botcha-failed label (red)
gh label create "botcha-failed" \
  --repo "$REPO" \
  --description "❌ BOTCHA verification failed" \
  --color "FEE2E2" \
  --force

echo "✅ BOTCHA labels created!"
echo ""
echo "Next steps:"
echo "1. Go to Settings > Branches > Add branch protection rule"
echo "2. Branch name pattern: main"
echo "3. Enable 'Require status checks to pass'"
echo "4. Enable 'Require labels' and add 'botcha-verified'"
