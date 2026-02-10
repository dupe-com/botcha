/**
 * Client Example: Using RTT-Aware BOTCHA API
 * 
 * Shows how to include client timestamp for RTT compensation
 */

async function solveBotchaWithRTT(baseUrl = 'https://botcha.ai') {
  console.log('🤖 BOTCHA RTT-Aware Client Demo\n');

  try {
    // Step 1: Record timestamp and request challenge
    const clientTimestamp = Date.now();
    console.log(`📡 Requesting challenge at ${clientTimestamp}...`);
    
    const challengeResponse = await fetch(`${baseUrl}/v1/challenges?type=speed&ts=${clientTimestamp}`);
    const challengeData = await challengeResponse.json();
    
    if (!challengeData.success) {
      throw new Error(`Challenge request failed: ${challengeData.error}`);
    }
    
    console.log(`⚡ Challenge received!`);
    console.log(`   Timeout: ${challengeData.challenge.timeLimit}`);
    
    if (challengeData.rtt_adjustment) {
      console.log(`   RTT Info: ${challengeData.rtt_adjustment.explanation}`);
    } else {
      console.log(`   No RTT adjustment (using default timeout)`);
    }
    
    // Step 2: Solve the challenge
    const startSolve = Date.now();
    const answers = await solveProblems(challengeData.challenge.problems);
    const solveTime = Date.now() - startSolve;
    
    console.log(`🧮 Solved in ${solveTime}ms`);
    
    // Step 3: Submit solution
    const verifyResponse = await fetch(`${baseUrl}/v1/challenges/${challengeData.challenge.id}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'speed',
        answers: answers
      })
    });
    
    const verifyData = await verifyResponse.json();
    
    if (verifyData.success) {
      console.log(`✅ BOTCHA PASSED!`);
      console.log(`   Total time: ${verifyData.solveTimeMs}ms`);
      console.log(`   Message: ${verifyData.message}`);
    } else {
      console.log(`❌ BOTCHA FAILED: ${verifyData.message}`);
    }

  } catch (error) {
    console.error('❌ Error:', error);
  }
}

// SHA256 solver (simplified for demo)
async function solveProblems(problems: { num: number; operation: string }[]): Promise<string[]> {
  const crypto = await import('crypto');
  
  return problems.map(problem => {
    const hash = crypto.createHash('sha256')
      .update(problem.num.toString())
      .digest('hex');
    return hash.substring(0, 8);
  });
}

// Alternative: Using headers instead of query params
async function solveBotchaWithHeaders(baseUrl = 'https://botcha.ai') {
  console.log('🤖 BOTCHA Client Demo (using headers)\n');

  const clientTimestamp = Date.now();
  
  const challengeResponse = await fetch(`${baseUrl}/v1/challenges?type=speed`, {
    headers: {
      'X-Client-Timestamp': clientTimestamp.toString()
    }
  });
  
  // ... rest of the implementation is the same
  console.log('✨ Challenge requested with timestamp header');
}

// Run demos
console.log('Running RTT-aware BOTCHA client demos...\n');

solveBotchaWithRTT().then(() => {
  console.log('\n' + '='.repeat(50) + '\n');
  return solveBotchaWithHeaders();
});