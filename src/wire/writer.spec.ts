import { describe, expect, it } from 'vitest';
import { SshReader } from './reader';
import { SshWriter } from './writer';

describe('SshWriter', () => {
  it('should write uint8', () => {
    const writer = new SshWriter();
    writer.writeUint8(0x12);
    writer.writeUint8(0x34);
    expect(writer.toUint8Array()).toEqual(new Uint8Array([0x12, 0x34]));
  });

  it('should write uint32', () => {
    const writer = new SshWriter();
    writer.writeUint32(0x12345678);
    expect(writer.toUint8Array()).toEqual(new Uint8Array([0x12, 0x34, 0x56, 0x78]));
  });

  it('should write uint64', () => {
    const writer = new SshWriter();
    writer.writeUint64(0x123456789abcdef0n);
    const expected = new Uint8Array([
      0x12, 0x34, 0x56, 0x78,
      0x9a, 0xbc, 0xde, 0xf0,
    ]);
    expect(writer.toUint8Array()).toEqual(expected);
  });

  it('should write bytes', () => {
    const writer = new SshWriter();
    writer.writeBytes(new Uint8Array([0x01, 0x02, 0x03]));
    expect(writer.toUint8Array()).toEqual(new Uint8Array([0x01, 0x02, 0x03]));
  });

  it('should write string', () => {
    const writer = new SshWriter();
    writer.writeString('hello');
    const reader = new SshReader(writer.toUint8Array());
    expect(reader.readString()).toBe('hello');
  });

  it('should write mpint', () => {
    const writer = new SshWriter();
    writer.writeMpInt(new Uint8Array([0x01, 0x02, 0x03]));
    const reader = new SshReader(writer.toUint8Array());
    expect(reader.readMpInt()).toEqual(new Uint8Array([0x01, 0x02, 0x03]));
  });

  it('should expand buffer when needed', () => {
    const writer = new SshWriter(2); // small initial size
    writer.writeUint32(0x12345678); // 4 bytes
    writer.writeUint32(0x9abcdef0); // 4 more bytes
    const expected = new Uint8Array([
      0x12, 0x34, 0x56, 0x78,
      0x9a, 0xbc, 0xde, 0xf0,
    ]);
    expect(writer.toUint8Array()).toEqual(expected);
  });
});
