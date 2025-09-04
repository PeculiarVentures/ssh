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
    const expected = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
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

  it('should write mpint with leading zero for high bit set', () => {
    const writer = new SshWriter();
    // Value with high bit set (0x80) should get a leading zero
    writer.writeMpInt(new Uint8Array([0x80, 0x01, 0x02]), true);
    const data = writer.toUint8Array();

    // Should have length 4 (3 original bytes + 1 leading zero)
    const expectedLength = new Uint8Array([0x00, 0x00, 0x00, 0x04]);
    const expectedValue = new Uint8Array([0x00, 0x80, 0x01, 0x02]);
    const expected = new Uint8Array(expectedLength.length + expectedValue.length);
    expected.set(expectedLength);
    expected.set(expectedValue, expectedLength.length);

    expect(data).toEqual(expected);

    // Test round-trip
    const reader = new SshReader(data);
    const roundTrip = reader.readMpInt(true);
    expect(roundTrip).toEqual(new Uint8Array([0x80, 0x01, 0x02]));
  });

  it('should write mpint without leading zero for low bit', () => {
    const writer = new SshWriter();
    // Value without high bit set (0x7F) should not get a leading zero
    writer.writeMpInt(new Uint8Array([0x7f, 0x01, 0x02]), true);
    const data = writer.toUint8Array();

    // Should have length 3 (no leading zero added)
    const expectedLength = new Uint8Array([0x00, 0x00, 0x00, 0x03]);
    const expectedValue = new Uint8Array([0x7f, 0x01, 0x02]);
    const expected = new Uint8Array(expectedLength.length + expectedValue.length);
    expected.set(expectedLength);
    expected.set(expectedValue, expectedLength.length);

    expect(data).toEqual(expected);

    // Test round-trip
    const reader = new SshReader(data);
    const roundTrip = reader.readMpInt(true);
    expect(roundTrip).toEqual(new Uint8Array([0x7f, 0x01, 0x02]));
  });

  it('should expand buffer when needed', () => {
    const writer = new SshWriter(2); // small initial size
    writer.writeUint32(0x12345678); // 4 bytes
    writer.writeUint32(0x9abcdef0); // 4 more bytes
    const expected = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
    expect(writer.toUint8Array()).toEqual(expected);
  });
});
