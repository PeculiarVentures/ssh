import { execSync } from 'child_process';
import { unlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const tmpDir = tmpdir();

// Helper to create temp file
export function createTempFile(content: string, ext = 'txt'): string {
  const filePath = join(tmpDir, `ssh-test-${Date.now()}.${ext}`);
  writeFileSync(filePath, content);
  return filePath;
}

// Helper to run ssh-keygen command
export function runSshKeygen(args: string[]): string {
  // Add -q flag to suppress informational messages
  const quietArgs = ['-q', ...args];
  return execSync(`ssh-keygen ${quietArgs.map(arg => `'${arg}'`).join(' ')}`, { encoding: 'utf8' });
}

// Helper to clean up temp files
export function cleanupTempFiles(...files: string[]): void {
  files.forEach(file => {
    try {
      unlinkSync(file);
    } catch {
      // Ignore errors
    }
  });
}
