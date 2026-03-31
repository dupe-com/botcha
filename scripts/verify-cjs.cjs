/**
 * CJS Compatibility Verification Script
 * Run after `bun run build` to verify the CJS output works.
 * Usage: node scripts/verify-cjs.cjs
 */
'use strict';

const path = require('path');
const fs = require('fs');
const ROOT = path.resolve(__dirname, '..');

let failed = 0;

function check(label, fn) {
  try {
    fn();
    console.log(`  ✓ ${label}`);
  } catch (err) {
    console.error(`  ✗ ${label}: ${err.message}`);
    failed++;
  }
}

console.log('\nVerifying CJS output...\n');

// 1. Files exist
check('dist/cjs/package.json marks type=commonjs', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'dist/cjs/package.json'), 'utf8'));
  if (pkg.type !== 'commonjs') throw new Error(`Expected "commonjs", got "${pkg.type}"`);
});

check('dist/cjs/lib/index.js exists', () => {
  if (!fs.existsSync(path.join(ROOT, 'dist/cjs/lib/index.js'))) throw new Error('Missing');
});

check('dist/cjs/lib/client/index.js exists', () => {
  if (!fs.existsSync(path.join(ROOT, 'dist/cjs/lib/client/index.js'))) throw new Error('Missing');
});

check('dist/cjs/src/middleware/tap-enhanced-verify.js exists', () => {
  if (!fs.existsSync(path.join(ROOT, 'dist/cjs/src/middleware/tap-enhanced-verify.js'))) throw new Error('Missing');
});

// 2. require() works
check('require("./dist/cjs/lib/index.js") exports botcha + verify + solve', () => {
  const mod = require(path.join(ROOT, 'dist/cjs/lib/index.js'));
  if (typeof mod.botcha !== 'object') throw new Error(`botcha not exported (got ${typeof mod.botcha})`);
  if (typeof mod.verify !== 'function') throw new Error(`verify not exported (got ${typeof mod.verify})`);
  if (typeof mod.solve !== 'function') throw new Error(`solve not exported (got ${typeof mod.solve})`);
});

check('require("./dist/cjs/lib/client/index.js") loads without error', () => {
  const mod = require(path.join(ROOT, 'dist/cjs/lib/client/index.js'));
  if (Object.keys(mod).length === 0) throw new Error('No exports');
});

check('require("./dist/cjs/src/middleware/tap-enhanced-verify.js") loads without error', () => {
  const mod = require(path.join(ROOT, 'dist/cjs/src/middleware/tap-enhanced-verify.js'));
  if (Object.keys(mod).length === 0) throw new Error('No exports');
});

if (failed > 0) {
  console.error(`\n${failed} check(s) failed.\n`);
  process.exit(1);
} else {
  console.log('\nAll CJS checks passed ✓\n');
}
