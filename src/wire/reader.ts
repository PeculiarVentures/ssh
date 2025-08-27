import type { ByteView } from '../types';

export class SshReader {
  private buffer: Uint8Array;
  private offset: number;

  constructor(data: ByteView) {
    this.buffer = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
    this.offset = 0;
  }

  readUint8(): number {
    if (this.offset >= this.buffer.length) {
      throw new Error('Buffer underflow',);
    }
    return this.buffer[this.offset++];
  }

  readUint32(): number {
    const value =
      (this.readUint8() << 24)
      | (this.readUint8() << 16)
      | (this.readUint8() << 8)
      | this.readUint8();
    return value >>> 0; // Ensure unsigned
  }

  readUint64(): bigint {
    const high = this.readUint32();
    const low = this.readUint32();
    return (BigInt(high) << 32n) | BigInt(low);
  }

  readBytes(length: number): Uint8Array {
    if (this.offset + length > this.buffer.length) {
      throw new Error('Buffer underflow');
    }
    const result = this.buffer.slice(this.offset, this.offset + length);
    this.offset += length;
    return result;
  }

  readString(): string {
    const length = this.readUint32();
    const bytes = this.readBytes(length,);
    return new TextDecoder().decode(bytes,);
  }

  readMpInt(): Uint8Array {
    const length = this.readUint32();
    return this.readBytes(length);
  }

  remaining(): number {
    return this.buffer.length - this.offset;
  }

  getOffset(): number {
    return this.offset;
  }

  seek(offset: number,): void {
    if (offset < 0 || offset > this.buffer.length) {
      throw new Error('Invalid offset');
    }
    this.offset = offset;
  }
}
