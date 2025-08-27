import { describe, expect, it } from 'vitest';
import type { ByteView } from './types';

describe('Common Types', () => {
  it('should export ByteView type', () => {
    const buffer: ByteView = new ArrayBuffer(8);
    expect(buffer).toBeDefined();
  });

  it('should accept Uint8Array as ByteView', () => {
    const buffer: ByteView = new Uint8Array(8);
    expect(buffer).toBeDefined();
    expect(buffer.length).toBe(8);
  });
});
