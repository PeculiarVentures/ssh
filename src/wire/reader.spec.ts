import { describe, expect, it } from 'vitest';
import { SshReader } from './reader';
import { SshWriter } from './writer';

describe('SshReader', () => {
  it('should read uint8', () => {
    const data = new Uint8Array([0x12, 0x34, 0x56]);
    const reader = new SshReader(data);
    expect(reader.readUint8()).toBe(0x12);
    expect(reader.readUint8()).toBe(0x34);
    expect(reader.readUint8()).toBe(0x56);
  });

  it('should read uint32', () => {
    const data = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const reader = new SshReader(data);
    expect(reader.readUint32()).toBe(0x12345678);
  });

  it('should read uint64', () => {
    const data = new Uint8Array([0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02]);
    const reader = new SshReader(data);
    expect(reader.readUint64()).toBe(0x100000002n);
  });

  it('should read bytes', () => {
    const data = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
    const reader = new SshReader(data);
    const bytes = reader.readBytes(3);
    expect(bytes).toEqual(new Uint8Array([0x01, 0x02, 0x03]));
  });

  it('should read string', () => {
    const writer = new SshWriter();
    writer.writeString('hello');
    const data = writer.toUint8Array();
    const reader = new SshReader(data);
    expect(reader.readString()).toBe('hello');
  });

  it('should read mpint', () => {
    const writer = new SshWriter();
    writer.writeMpInt(new Uint8Array([0x01, 0x02, 0x03]));
    const data = writer.toUint8Array();
    const reader = new SshReader(data);
    expect(reader.readMpInt()).toEqual(new Uint8Array([0x01, 0x02, 0x03]));
  });

  it('should throw on buffer underflow', () => {
    const data = new Uint8Array([0x01]);
    const reader = new SshReader(data);
    reader.readUint8(); // consume the byte
    expect(() => reader.readUint8()).toThrow('Buffer underflow');
  });
});
