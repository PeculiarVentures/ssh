import { InvalidFormatError, UnexpectedEOFError } from '../errors.js';
import type { ByteView } from '../types';
import { decoder } from '../utils';

export class SshReader {
  private buffer: Uint8Array;
  private offset: number;

  constructor(data: ByteView) {
    this.buffer = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
    this.offset = 0;
  }

  /**
   * Reads a single byte from the buffer
   * @throws {UnexpectedEOFError} When buffer underflow occurs
   */
  readUint8(): number {
    if (this.offset >= this.buffer.length) {
      throw new UnexpectedEOFError(1, 0);
    }
    return this.buffer[this.offset++];
  }

  readUint32(): number {
    const value =
      (this.readUint8() << 24) |
      (this.readUint8() << 16) |
      (this.readUint8() << 8) |
      this.readUint8();
    return value >>> 0; // Ensure unsigned
  }

  readUint64(): bigint {
    const high = this.readUint32();
    const low = this.readUint32();
    return (BigInt(high) << 32n) | BigInt(low);
  }

  /**
   * Reads specified number of bytes from the buffer
   * @param length Number of bytes to read
   * @returns A view (subarray) of the buffer data (not a copy)
   * @throws {UnexpectedEOFError} When not enough bytes available
   */
  readBytes(length: number): Uint8Array {
    if (length < 0) {
      throw new InvalidFormatError(`Invalid length: ${length}`);
    }
    if (this.offset + length > this.buffer.length) {
      throw new UnexpectedEOFError(length, this.buffer.length - this.offset);
    }
    const result = this.buffer.subarray(this.offset, this.offset + length);
    this.offset += length;
    return result;
  }

  /**
   * Reads a UTF-8 string with 32-bit length prefix
   * SSH wire protocol format: length (4 bytes) + string data
   */
  readString(): string {
    const length = this.readUint32();
    const bytes = this.readBytes(length);
    return decoder.decode(bytes);
  }

  /**
   * Reads an arbitrary precision integer (mpint) with 32-bit length prefix
   * SSH wire protocol format: length (4 bytes) + integer data (big-endian)
   */
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

  /**
   * Seeks to a specific offset in the buffer
   * @param offset Target offset (0-based)
   * @throws {InvalidFormatError} When offset is out of bounds
   */
  seek(offset: number): void {
    if (offset < 0 || offset > this.buffer.length) {
      throw new InvalidFormatError(
        `Invalid offset: ${offset}. Buffer length: ${this.buffer.length}`,
      );
    }
    this.offset = offset;
  }
}
