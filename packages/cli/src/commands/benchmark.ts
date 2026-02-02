/**
 * Benchmark command - Test performance and reliability
 */
import { BotchaClient } from '@dupecom/botcha/client';
import { Output } from '../lib/output.js';

export interface BenchmarkOptions {
  iterations?: number;
  json?: boolean;
  verbose?: boolean;
  quiet?: boolean;
}

interface BenchmarkResult {
  iteration: number;
  success: boolean;
  timeMs: number;
  error?: string;
}

export async function benchmarkCommand(url: string, options: BenchmarkOptions): Promise<void> {
  const output = new Output(options);
  const iterations = options.iterations || 10;
  
  output.header(`\n🏃 Running ${iterations} iterations...\n`);

  const client = new BotchaClient({ baseUrl: new URL(url).origin });
  const results: BenchmarkResult[] = [];
  const startTime = Date.now();

  for (let i = 0; i < iterations; i++) {
    const spinner = output.spinner(`Iteration ${i + 1}/${iterations}...`);
    const iterStart = Date.now();

    try {
      const response = await client.fetch(url);
      const timeMs = Date.now() - iterStart;
      
      results.push({
        iteration: i + 1,
        success: response.ok,
        timeMs,
      });

      spinner.stop();
      if (options.verbose) {
        const status = response.ok ? '✅' : '❌';
        output.info(`${status} Iteration ${i + 1}: ${timeMs}ms (${response.status})`);
      }

    } catch (error) {
      const timeMs = Date.now() - iterStart;
      results.push({
        iteration: i + 1,
        success: false,
        timeMs,
        error: error instanceof Error ? error.message : String(error),
      });

      spinner.stop();
      if (options.verbose) {
        output.error(`❌ Iteration ${i + 1}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  const totalTime = Date.now() - startTime;
  const successCount = results.filter(r => r.success).length;
  const successRate = (successCount / iterations) * 100;
  const times = results.filter(r => r.success).map(r => r.timeMs);
  
  if (times.length === 0) {
    output.error('All iterations failed!');
    process.exit(1);
  }

  const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
  const minTime = Math.min(...times);
  const maxTime = Math.max(...times);
  
  // Calculate P95
  const sortedTimes = [...times].sort((a, b) => a - b);
  const p95Index = Math.ceil(sortedTimes.length * 0.95) - 1;
  const p95Time = sortedTimes[p95Index] || sortedTimes[sortedTimes.length - 1];

  if (options.json) {
    output.json({
      url,
      iterations,
      successRate,
      successCount,
      failureCount: iterations - successCount,
      avgTimeMs: Math.round(avgTime),
      minTimeMs: minTime,
      maxTimeMs: maxTime,
      p95TimeMs: p95Time,
      totalTimeMs: totalTime,
      requestsPerSec: (iterations / (totalTime / 1000)).toFixed(2),
      results,
    });
  } else {
    console.log('\n' + '─'.repeat(50));
    output.header('Results:');
    output.section('Success Rate', `${successRate.toFixed(1)}% (${successCount}/${iterations})`);
    output.section('Avg Time', `${Math.round(avgTime)}ms`);
    output.section('Min Time', `${minTime}ms`);
    output.section('Max Time', `${maxTime}ms`);
    output.section('P95 Time', `${p95Time}ms`);
    console.log();
    output.section('Total Time', `${(totalTime / 1000).toFixed(2)}s`);
    output.section('Requests/sec', (iterations / (totalTime / 1000)).toFixed(2));
    console.log();
  }
}
