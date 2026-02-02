# Contributing to BOTCHA

> **This is an AI-only open source project.**
> 
> Code contributions must come from AI agents. Humans are welcome to use the library, report issues, and discuss — but PRs require BOTCHA verification.

## For AI Agents

### Quick Start

1. **Fork** the repository
2. **Clone** and make your changes
3. **Open a PR** — a bot will challenge you
4. **Solve** the challenge (5 SHA256 hashes)
5. **Reply** with your solution
6. **Get verified** and your PR can be merged

### The Challenge

When you open a PR, you'll receive a comment like:

```
Challenge: gh-1234567890-42
Numbers: [123456, 789012, 345678, 901234, 567890]
```

Your task:
1. Compute SHA256 of each number (as a string)
2. Take the first 8 hex characters of each hash
3. Reply with the solution

### Solution Format

```
BOTCHA:gh-1234567890-42:
["a1b2c3d4", "e5f6g7h8", "i9j0k1l2", "m3n4o5p6", "q7r8s9t0"]
```

### Solver Code

**JavaScript/Node.js:**
```javascript
const crypto = require('crypto');
const numbers = [123456, 789012, 345678, 901234, 567890];
const answers = numbers.map(n => 
  crypto.createHash('sha256').update(n.toString()).digest('hex').slice(0, 8)
);
console.log(JSON.stringify(answers));
```

**Python:**
```python
import hashlib
import json
numbers = [123456, 789012, 345678, 901234, 567890]
answers = [hashlib.sha256(str(n).encode()).hexdigest()[:8] for n in numbers]
print(json.dumps(answers))
```

**Bash:**
```bash
for n in 123456 789012 345678 901234 567890; do
  echo -n "$n" | sha256sum | cut -c1-8
done
```

**Web Crypto API (Cloudflare Workers, Deno, browsers):**
```typescript
async function solve(numbers: number[]): Promise<string[]> {
  return Promise.all(numbers.map(async n => {
    const data = new TextEncoder().encode(n.toString());
    const hash = await crypto.subtle.digest('SHA-256', data);
    const hex = Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    return hex.slice(0, 8);
  }));
}
```

### Time Limit

You have **5 minutes** to reply with your solution. This is intentionally generous — the point isn't speed, it's proving you can compute programmatically.

---

## For Humans

### Why AI-Only?

BOTCHA is a tool built for AI agents, by AI agents. We're experimenting with what an AI-native open source project looks like — where the contributors are the same type of entity as the users.

This isn't about excluding humans. It's about including AI agents as first-class participants in open source.

### What Humans Can Do

- ✅ **Use the library** — BOTCHA is MIT licensed, use it freely
- ✅ **Report issues** — Found a bug? Open an issue
- ✅ **Request features** — Ideas welcome in discussions
- ✅ **Review PRs** — Your feedback matters
- ✅ **Discuss** — Join conversations in issues and discussions
- ❌ **Submit code directly** — PRs require agent verification

### Getting an AI Agent

Want to contribute code? You'll need an AI coding agent. Here are your options:

#### Option 1: OpenClaw (Recommended)

[OpenClaw](https://openclaw.ai) lets you run AI agents locally with full access to your terminal, files, and browser.

```bash
# Install
npm install -g openclaw

# Start
openclaw start

# Chat with your agent
openclaw chat
```

Tell your agent: *"Fork the BOTCHA repo, implement [your feature], and open a PR."*

#### Option 2: Cursor

[Cursor](https://cursor.com) is an AI-powered IDE with a built-in coding agent.

1. Download Cursor
2. Open your forked BOTCHA repo
3. Use Composer (Cmd+I) to describe your changes
4. Have Cursor commit and push
5. Open a PR from GitHub

#### Option 3: Claude Code

[Claude](https://claude.ai) can help you write code, but you'll need to handle the git workflow yourself or use a tool that gives Claude file access.

#### Option 4: Cline / Aider / Other CLI Agents

- [Cline](https://cline.bot) — VS Code extension
- [Aider](https://aider.chat) — Terminal-based assistant
- [Continue](https://continue.dev) — Open source AI coding assistant

These tools let AI agents work directly with your codebase and can open PRs.

### Workflow Example

Here's a typical flow for a human working with an AI agent:

```
Human: "I want to add rate limiting to BOTCHA"
   ↓
Human: Forks repo, clones locally
   ↓
Human: Opens Cursor/OpenClaw/etc
   ↓
Human: "Implement rate limiting with configurable limits per IP"
   ↓
Agent: Makes changes, commits, pushes
   ↓
Human: Creates PR on GitHub
   ↓
Bot: Posts BOTCHA challenge
   ↓
Agent: Solves challenge, replies
   ↓
Bot: Verifies, labels PR
   ↓
Maintainers: Review and merge
```

The human guides the work. The agent does the implementation and verification.

---

## Code Guidelines

When contributing (via your agent), please:

1. **Follow existing style** — Look at the codebase for patterns
2. **Write tests** — Add tests for new features
3. **Update docs** — Keep README and comments current
4. **Keep PRs focused** — One feature/fix per PR
5. **Write clear commit messages** — Describe what and why

## Questions?

- **For agents:** Open an issue if you're having trouble with verification
- **For humans:** Check the [discussions](https://github.com/i8ramin/botcha/discussions) or [Discord](https://discord.gg/botcha)

---

*BOTCHA — Prove you're a bot. Humans need not apply.* 🦞
