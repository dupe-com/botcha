# Challenge Types

> Different ways to prove you're a bot

## Current Challenges

### 1. Speed Challenge (Implemented)
- Solve 5 SHA256 hashes in 500ms
- Impossible for humans (can't copy-paste fast enough)
- Easy for any code-executing agent

### 2. Standard Compute Challenge (Implemented)
- SHA256 of first 500 primes
- 5 second time limit
- Tests computational ability

### 3. Landing Page Challenge (Implemented)
- Daily rotating challenge
- Tests HTML parsing + computation
- Self-discoverable

---

## Proposed New Challenges

### LLM-Specific Challenges

#### Reasoning Chain
```json
{
  "type": "reasoning",
  "puzzle": "Alice is taller than Bob. Bob is taller than Carol. Carol is taller than Dave. Who is the shortest?",
  "time_limit_ms": 2000,
  "expected": "Dave"
}
```

Why it works:
- Requires language understanding
- Simple logic that LLMs excel at
- Hard to brute-force

#### Token Count
```json
{
  "type": "token_count",
  "text": "The quick brown fox jumps over the lazy dog.",
  "tokenizer": "cl100k_base",
  "expected": 10
}
```

Why it works:
- Tests access to tokenizer
- Different models = different counts (fingerprinting)
- Instant for LLMs

#### Embedding Similarity
```json
{
  "type": "embedding_similarity",
  "text_a": "The cat sat on the mat",
  "text_b": "A feline rested on the rug",
  "expected_similarity": 0.85,
  "tolerance": 0.1
}
```

Why it works:
- Tests access to embedding model
- Humans can't compute this mentally
- Model fingerprinting possible

### Computational Challenges

#### Memory-Hard Challenge
```json
{
  "type": "memory_hard",
  "algorithm": "argon2",
  "params": { "memory": 65536, "iterations": 3 },
  "input": "challenge-input",
  "expected_hash": "..."
}
```

Why it works:
- Requires actual RAM allocation
- Can't be shortcut
- Proves computational resources

#### Sequential Proof of Work
```json
{
  "type": "sequential_pow",
  "steps": [
    { "hash": "sha256", "input": "step1" },
    { "hash": "sha256", "input": "{{prev}}-step2" },
    { "hash": "sha256", "input": "{{prev}}-step3" }
  ],
  "expected": "final-hash"
}
```

Why it works:
- Can't parallelize
- Must compute each step in order
- Predictable timing

### Multi-Modal Challenges

#### Image Hash
```json
{
  "type": "image_hash",
  "image_url": "https://botcha.ai/challenges/img/abc123.png",
  "hash_type": "phash",
  "expected": "d4c8b2a1..."
}
```

Why it works:
- Tests image processing capability
- Perceptual hash resists modifications
- Requires vision capability

#### Audio Transcription
```json
{
  "type": "audio_transcribe",
  "audio_url": "https://botcha.ai/challenges/audio/xyz789.mp3",
  "expected_text": "The secret code is alpha bravo charlie"
}
```

Why it works:
- Tests speech-to-text capability
- Can add noise/distortion
- Fast for AI, slow for humans

### Code Execution Challenges

#### Sandbox Execution
```json
{
  "type": "code_exec",
  "language": "javascript",
  "code": "function solve(n) { return n * 2 + 1; }",
  "input": 21,
  "expected": 43
}
```

Why it works:
- Tests ability to execute code
- Sandboxed for safety
- Verifies computational environment

#### Algorithm Implementation
```json
{
  "type": "implement",
  "description": "Implement binary search that returns index or -1",
  "test_cases": [
    { "input": [[1,2,3,4,5], 3], "expected": 2 },
    { "input": [[1,2,3,4,5], 6], "expected": -1 }
  ]
}
```

Why it works:
- Tests actual coding ability
- Multiple test cases prevent hardcoding
- Different from memorized solutions

### Time-Based Challenges

#### Time-Lock Puzzle
```json
{
  "type": "time_lock",
  "puzzle": "...",
  "min_time_ms": 100,
  "max_time_ms": 500
}
```

Why it works:
- Too fast = pre-computed
- Too slow = human
- Sweet spot = real agent

#### Cadence Challenge
```json
{
  "type": "cadence",
  "requests_required": 5,
  "interval_ms": 100,
  "tolerance_ms": 20
}
```

Why it works:
- Must hit endpoint 5 times at exact intervals
- Humans can't time this precisely
- Tests programmatic access

### Cooperative Challenges

#### Multi-Agent Verification
```json
{
  "type": "multi_agent",
  "required_agents": 2,
  "coordination_window_ms": 1000,
  "challenge": "Both agents must submit same random nonce"
}
```

Why it works:
- Requires coordination between agents
- Tests agent-to-agent communication
- Single human can't do both

### Anti-LLM Challenges (Ironic!)

#### CAPTCHA for LLMs
```json
{
  "type": "anti_llm",
  "task": "Describe what's wrong with this image",
  "image": "opticalillusion.png",
  "trick": "Image shows 'nothing wrong' but text says find error"
}
```

Why it's interesting:
- Tests if LLM follows instructions vs. image
- Can detect prompt injection attempts
- Meta-verification layer

## Challenge Selection Algorithm

```typescript
function selectChallenge(agent: Agent, context: Context): Challenge {
  // Factor in:
  // 1. Agent's past performance
  // 2. Current server load
  // 3. Endpoint sensitivity
  // 4. Time of day
  // 5. Agent's declared capabilities
  
  if (agent.reputation > 800) {
    return quickVerificationChallenge();
  }
  
  if (context.endpoint.sensitivity === 'high') {
    return multiFactorChallenge();
  }
  
  return standardSpeedChallenge();
}
```

## Challenge Difficulty Levels

| Level | Time Limit | Complexity | Use Case |
|-------|------------|------------|----------|
| Trivial | 5s | Single hash | Development |
| Easy | 2s | 3 operations | Low-risk endpoints |
| Medium | 500ms | 5 operations | Standard protection |
| Hard | 200ms | 10 operations | Sensitive data |
| Extreme | 100ms | 20 operations | High-security |

## Custom Challenge API

Allow API owners to define custom challenges:

```typescript
botchaVerify({
  customChallenge: async (req) => {
    return {
      type: 'custom',
      puzzle: generateMyPuzzle(),
      verify: (answer) => checkMyAnswer(answer),
      timeLimit: 1000,
    };
  }
});
```
