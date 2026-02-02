/**
 * Terminal output utilities with colored and formatted output
 */
import chalk from 'chalk';

export interface OutputOptions {
  json?: boolean;
  verbose?: boolean;
  quiet?: boolean;
}

export class Output {
  constructor(private options: OutputOptions = {}) {}

  private suppressNonJson(): boolean {
    return Boolean(this.options.quiet || this.options.json);
  }

  success(message: string): void {
    if (this.suppressNonJson()) return;
    console.log(chalk.green('✅'), message);
  }

  error(message: string): void {
    if (this.suppressNonJson()) return;
    console.error(chalk.red('❌'), message);
  }

  info(message: string): void {
    if (this.suppressNonJson()) return;
    console.log(chalk.blue('ℹ️ '), message);
  }

  warn(message: string): void {
    if (this.suppressNonJson()) return;
    console.warn(chalk.yellow('⚠️ '), message);
  }

  debug(message: string): void {
    if (this.suppressNonJson() || !this.options.verbose) return;
    console.log(chalk.gray('DEBUG:'), message);
  }

  header(message: string): void {
    if (this.suppressNonJson()) return;
    console.log(chalk.bold.cyan(message));
  }

  section(label: string, value: string | number): void {
    if (this.suppressNonJson()) return;
    console.log(`   ${chalk.dim(label)}: ${value}`);
  }

  json(data: unknown): void {
    console.log(JSON.stringify(data, null, 2));
  }

  table(headers: string[], rows: string[][]): void {
    if (this.suppressNonJson()) return;
    
    const colWidths = headers.map((h, i) => {
      const values = [h, ...rows.map(r => r[i] || '')];
      return Math.max(...values.map(v => v.length));
    });

    const formatRow = (row: string[]) => {
      return row.map((cell, i) => cell.padEnd(colWidths[i])).join('  ');
    };

    console.log(chalk.bold(formatRow(headers)));
    console.log(chalk.dim('─'.repeat(colWidths.reduce((a, b) => a + b + 2, 0))));
    rows.forEach(row => console.log(formatRow(row)));
  }

  spinner(message: string): { stop: (finalMessage?: string) => void } {
    if (this.suppressNonJson()) {
      return { stop: () => {} };
    }

    const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let i = 0;
    let stopped = false;

    const interval = setInterval(() => {
      if (!stopped) {
        process.stdout.write(`\r${chalk.cyan(frames[i])} ${message}`);
        i = (i + 1) % frames.length;
      }
    }, 80);

    return {
      stop: (finalMessage?: string) => {
        stopped = true;
        clearInterval(interval);
        process.stdout.write('\r' + ' '.repeat(message.length + 2) + '\r');
        if (finalMessage) {
          console.log(finalMessage);
        }
      },
    };
  }

  timing(label: string, ms: number): void {
    if (this.suppressNonJson()) return;
    
    const color = ms < 100 ? chalk.green : ms < 500 ? chalk.yellow : chalk.red;
    console.log(`   ${chalk.dim(label)}: ${color(`${ms}ms`)}`);
  }
}

export function formatUrl(url: string): string {
  return chalk.underline.blue(url);
}

export function formatHeaders(headers: Record<string, string>): void {
  console.log(chalk.bold('\nHeaders:'));
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase().startsWith('x-botcha-')) {
      console.log(`  ${chalk.cyan(key)}: ${value}`);
    }
  }
}
