/**
 * RTT-Aware Speed Challenge Demo
 * 
 * Shows how the new RTT compensation works to make challenges fair
 * for agents with different network latencies.
 */

import { generateSpeedChallenge, verifySpeedChallenge } from '../src/challenges/speed.js';
import crypto from 'crypto';

async function solveChallenge(problems: { num: number; operation: string }[]): Promise<string[]> {
  return problems.map(problem => {
    const hash = crypto.createHash('sha256')
      .update(problem.num.toString())
      .digest('hex');
    return hash.substring(0, 8);
  });
}

async function demoRTTCompensation() {
  console.log('🚀 RTT-Aware Speed Challenge Demo\n');

  // Simulate different network conditions
  const scenarios = [
    { name: 'Local (no latency)', rtt: 0 },
    { name: 'Good connection', rtt: 50 },
    { name: 'Average connection', rtt: 150 },
    { name: 'Slow connection', rtt: 300 },
    { name: 'Very slow connection', rtt: 500 },
  ];

  for (const scenario of scenarios) {
    console.log(`📡 Testing: ${scenario.name} (${scenario.rtt}ms RTT)`);
    
    // Simulate client timestamp (subtract RTT to simulate network delay)
    const clientTimestamp = scenario.rtt === 0 ? undefined : Date.now() - scenario.rtt;
    
    // Generate challenge
    const challenge = generateSpeedChallenge(clientTimestamp);
    
    console.log(`   Base timeout: 500ms`);
    if (challenge.rttInfo) {
      console.log(`   Measured RTT: ${challenge.rttInfo.measuredRtt}ms`);
      console.log(`   Adjusted timeout: ${challenge.rttInfo.adjustedTimeout}ms`);
      console.log(`   Adjustment: ${challenge.rttInfo.explanation}`);
    } else {
      console.log(`   No RTT adjustment (using default 500ms)`);
    }
    
    // Solve the challenge (simulate AI agent computation time)
    const startTime = Date.now();
    const answers = await solveChallenge(challenge.challenges);
    const computeTime = Date.now() - startTime;
    
    console.log(`   Compute time: ${computeTime}ms`);
    
    // Verify solution
    const result = verifySpeedChallenge(challenge.id, answers);
    
    if (result.valid) {
      console.log(`   ✅ PASSED in ${result.solveTimeMs}ms`);
      if (result.rttInfo) {
        const efficiency = (result.rttInfo.actualTime / result.rttInfo.adjustedTimeout * 100).toFixed(1);
        console.log(`   Efficiency: ${efficiency}% of adjusted timeout`);
      }
    } else {
      console.log(`   ❌ FAILED: ${result.reason}`);
    }
    
    console.log('');
  }

  console.log('💡 Key Benefits:');
  console.log('   - Agents with slow networks get fair timeouts');
  console.log('   - Still impossible for humans (even with extra time)');
  console.log('   - Pure computation time remains 500ms baseline');
  console.log('   - Network latency is compensated automatically');
}

// Run the demo
demoRTTCompensation().catch(console.error);