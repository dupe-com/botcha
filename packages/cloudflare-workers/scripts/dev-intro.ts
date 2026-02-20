#!/usr/bin/env bun

/**
 * Display BOTCHA ASCII intro and start wrangler dev
 */

import { spawn } from 'child_process';

const portArgIdx = process.argv.indexOf('--port');
const PORT = (portArgIdx !== -1 ? process.argv[portArgIdx + 1] : null) || process.env.PORT || '8787';
const HOST = process.env.HOST || 'localhost';

const intro = `
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  ██████╗  ██████╗ ████████╗ ██████╗██╗  ██╗ █████╗           ║
║  ██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██║  ██║██╔══██╗          ║
║  ██████╔╝██║   ██║   ██║   ██║     ███████║███████║          ║
║  ██╔══██╗██║   ██║   ██║   ██║     ██╔══██║██╔══██║          ║
║  ██████╔╝╚██████╔╝   ██║   ╚██████╗██║  ██║██║  ██║          ║
║  ╚═════╝  ╚═════╝    ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝          ║
║                                                              ║
║  Prove you're a bot. Humans need not apply.                  ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  Server: http://${HOST}:${PORT}                               ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  CHALLENGES                                                  ║
║  GET  /v1/challenges            Hybrid challenge (default)   ║
║  GET  /v1/challenges?type=speed Speed-only (SHA256 <500ms)   ║
║  GET  /v1/reasoning             Reasoning challenge (LLM)    ║
║  GET  /v1/hybrid                Hybrid (speed + reasoning)   ║
║  GET  /v1/challenge/stream      SSE streaming challenge      ║
║                                                              ║
║  TOKEN FLOW                                                  ║
║  GET  /v1/token                 Get challenge for JWT        ║
║  POST /v1/token/verify          Verify & get JWT token       ║
║  GET  /agent-only               Protected (requires JWT)     ║
║                                                              ║
║  BADGES                                                      ║
║  GET  /badge/:id                Badge verification (HTML)    ║
║  GET  /badge/:id/image          Badge image (SVG)            ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  Starting Wrangler dev server...                             ║
╚══════════════════════════════════════════════════════════════╝
`;

console.log(intro);

// Start wrangler dev from source (bypasses dist/ so changes hot-reload)
const proc = spawn('wrangler', ['dev', 'src/index.tsx', '--port', PORT], {
  stdio: 'inherit',
});

// Exit with the same code as wrangler
proc.on('exit', (code) => {
  process.exit(code || 0);
});
