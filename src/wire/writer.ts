import { InvalidFormatError } from '../errors';
import type { ByteView } from '../types';
import { encoder } from '../utils';

export class SshWriter {
  private buffer: Uint8Array;
  private offset: number;

  constructor(initialSize = 1024) {
    this.buffer = new Uint8Array(initialSize);
    this.offset = 0;
  }

  private ensureCapacity(additional: number): void {
    const required = this.offset + additional;
    if (required > this.buffer.length) {
      const newSize = Math.max(required, this.buffer.length * 2);
      const newBuffer = new Uint8Array(newSize);
      newBuffer.set(this.buffer.subarray(0, this.offset));
      this.buffer = newBuffer;
    }
  }

  /**
   * Reserve capacity for future writes to avoid reallocations
   * @param minCapacity Minimum capacity to reserve
   */
  reserve(minCapacity: number): void {
    if (minCapacity > this.buffer.length) {
      const newBuffer = new Uint8Array(minCapacity);
      newBuffer.set(this.buffer.subarray(0, this.offset));
      this.buffer = newBuffer;
    }
  }

  writeUint8(value: number): void {
    this.ensureCapacity(1);
    this.buffer[this.offset++] = value & 0xff;
  }

  writeUint32(value: number): void {
    this.ensureCapacity(4);
    this.buffer[this.offset++] = (value >>> 24) & 0xff;
    this.buffer[this.offset++] = (value >>> 16) & 0xff;
    this.buffer[this.offset++] = (value >>> 8) & 0xff;
    this.buffer[this.offset++] = value & 0xff;
  }

  writeUint64(value: bigint): void {
    this.ensureCapacity(8);
    const high = Number(value >> 32n);
    const low = Number(value & 0xffffffffn);
    this.writeUint32(high);
    this.writeUint32(low);
  }

  writeBytes(data: ByteView): void {
    const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
    this.ensureCapacity(bytes.length);
    this.buffer.set(bytes, this.offset);
    this.offset += bytes.length;
  }

  writeString(value: string): void {
    const bytes = encoder.encode(value);
    this.writeUint32(bytes.length);
    this.writeBytes(bytes);
  }

  writeMpInt(value: ByteView): void {
    const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : value;
    this.writeUint32(bytes.length);
    this.writeBytes(bytes);
  }

  /**
   * Returns the written data as a Uint8Array
   * @returns A view (subarray) of the internal buffer (not a copy)
   */
  toUint8Array(): Uint8Array {
    return this.buffer.subarray(0, this.offset);
  }

  getOffset(): number {
    return this.offset;
  }

  seek(offset: number): void {
    if (offset < 0 || offset > this.buffer.length) {
      throw new InvalidFormatError('Invalid offset');
    }
    this.offset = offset;
  }
}
