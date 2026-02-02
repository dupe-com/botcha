import express, { Express } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { botchaVerify } from './middleware/verify.js';
import { generateChallenge, verifyChallenge } from './challenges/compute.js';
import { generateSpeedChallenge, verifySpeedChallenge } from './challenges/speed.js';
import { TRUSTED_PROVIDERS } from './utils/signature.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app: Express = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// CORS + BOTCHA headers
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', '*');
  
  // BOTCHA discovery headers
  res.header('X-Botcha-Version', '0.3.0');
  res.header('X-Botcha-Enabled', 'true');
  res.header('X-Botcha-Methods', 'speed-challenge,standard-challenge,web-bot-auth');
  res.header('X-Botcha-Docs', 'https://botcha.ai/openapi.json');
  
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Landing page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// API info
app.get('/api', (req, res) => {
  res.json({
    name: 'BOTCHA',
    version: '0.3.0',
    tagline: 'Prove you are a bot. Humans need not apply.',
    endpoints: {
      '/api': 'This info',
      '/api/challenge': 'Standard challenge (GET new, POST verify)',
      '/api/speed-challenge': '⚡ Speed challenge - 500ms to solve 5 problems',
      '/agent-only': 'Protected endpoint',
    },
    verification: {
      methods: [
        'Web Bot Auth (cryptographic signature)',
        'Speed Challenge (500ms time limit)',
        'Standard Challenge (5s time limit)',
        'X-Agent-Identity header (testing)',
      ],
      trustedProviders: TRUSTED_PROVIDERS,
    },
    discovery: {
      openapi: 'https://botcha.ai/openapi.json',
      aiPlugin: 'https://botcha.ai/.well-known/ai-plugin.json',
      aiTxt: 'https://botcha.ai/ai.txt',
      robotsTxt: 'https://botcha.ai/robots.txt',
      npm: 'https://www.npmjs.com/package/@dupecom/botcha',
      github: 'https://github.com/i8ramin/botcha',
    },
  });
});

// Standard challenge
app.get('/api/challenge', (req, res) => {
  const difficulty = (req.query.difficulty as 'easy' | 'medium' | 'hard') || 'medium';
  const challenge = generateChallenge(difficulty);
  res.json({ success: true, challenge });
});

app.post('/api/challenge', (req, res) => {
  const { id, answer } = req.body;
  if (!id || !answer) {
    return res.status(400).json({ success: false, error: 'Missing id or answer' });
  }
  const result = verifyChallenge(id, answer);
  res.json({
    success: result.valid,
    message: result.valid ? '✅ Challenge passed!' : `❌ ${result.reason}`,
    solveTime: result.timeMs,
  });
});

// ⚡ SPEED CHALLENGE - The human killer
app.get('/api/speed-challenge', (req, res) => {
  const challenge = generateSpeedChallenge();
  res.json({
    success: true,
    warning: '⚡ SPEED CHALLENGE: You have 500ms to solve ALL 5 problems!',
    challenge: {
      id: challenge.id,
      problems: challenge.challenges,
      timeLimit: `${challenge.timeLimit}ms`,
      instructions: challenge.instructions,
    },
    tip: 'Humans cannot copy-paste fast enough. Only real AI agents can pass.',
  });
});

app.post('/api/speed-challenge', (req, res) => {
  const { id, answers } = req.body;
  if (!id || !answers) {
    return res.status(400).json({ success: false, error: 'Missing id or answers array' });
  }
  
  const result = verifySpeedChallenge(id, answers);
  
  res.json({
    success: result.valid,
    message: result.valid 
      ? `⚡ SPEED TEST PASSED in ${result.solveTimeMs}ms! You are definitely an AI.`
      : `❌ ${result.reason}`,
    solveTimeMs: result.solveTimeMs,
    verdict: result.valid ? '🤖 VERIFIED AI AGENT' : '🚫 LIKELY HUMAN (too slow)',
  });
});

// Protected endpoint
app.get('/agent-only', botchaVerify(), (req, res) => {
  res.json({
    success: true,
    message: '🤖 Welcome, fellow agent!',
    verified: true,
    agent: (req as any).agent,
    method: (req as any).verificationMethod,
    timestamp: new Date().toISOString(),
    secret: 'The humans will never see this. Their fingers are too slow. 🤫',
  });
});

app.listen(PORT, () => {
  // Clear console on restart
  console.clear();
  
  const c = '\x1b[36m';
  const magenta = '\x1b[35m';
  const yellow = '\x1b[33m';
  const green = '\x1b[32m';
  const dim = '\x1b[2m';
  const r = '\x1b[0m';
  
  console.log(`
${c}╔══════════════════════════════════════════════════════╗${r}
${c}║${r}                                                      ${c}║${r}
${c}║${r}  ${magenta}██████╗  ██████╗ ████████╗ ██████╗██╗  ██╗ █████╗${r}   ${c}║${r}
${c}║${r}  ${magenta}██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██║  ██║██╔══██╗${r}  ${c}║${r}
${c}║${r}  ${magenta}██████╔╝██║   ██║   ██║   ██║     ███████║███████║${r}  ${c}║${r}
${c}║${r}  ${magenta}██╔══██╗██║   ██║   ██║   ██║     ██╔══██║██╔══██║${r}  ${c}║${r}
${c}║${r}  ${magenta}██████╔╝╚██████╔╝   ██║   ╚██████╗██║  ██║██║  ██║${r}  ${c}║${r}
${c}║${r}  ${magenta}╚═════╝  ╚═════╝    ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝${r}  ${c}║${r}
${c}║${r}                                                      ${c}║${r}
${c}║${r}  ${dim}Prove you're a bot. Humans need not apply.${r}          ${c}║${r}
${c}║${r}                                                      ${c}║${r}
${c}╠══════════════════════════════════════════════════════╣${r}
${c}║${r}                                                      ${c}║${r}
${c}║${r}  ${yellow}🤖 Server${r}     ${green}http://localhost:${PORT}${r}                 ${c}║${r}
${c}║${r}  ${yellow}📚 API${r}        ${dim}/api${r}                                  ${c}║${r}
${c}║${r}  ${yellow}⚡ Challenge${r}  ${dim}/api/speed-challenge${r}                  ${c}║${r}
${c}║${r}  ${yellow}🔒 Protected${r}  ${dim}/agent-only${r}                           ${c}║${r}
${c}║${r}  ${yellow}📖 OpenAPI${r}    ${dim}/openapi.json${r}                         ${c}║${r}
${c}║${r}                                                      ${c}║${r}
${c}╚══════════════════════════════════════════════════════╝${r}
`);
});

export default app;
