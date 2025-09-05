import { InvalidFormatError } from '../errors';
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

  writeBytes(data: Uint8Array): void {
    this.ensureCapacity(data.length);
    this.buffer.set(data, this.offset);
    this.offset += data.length;
  }

  writeString(value: string): void {
    const bytes = encoder.encode(value);
    this.writeUint32(bytes.length);
    this.writeBytes(bytes);
  }

  writeMpInt(value: Uint8Array, sshEncoding = false): void {
    if (sshEncoding && value.length > 0 && (value[0] & 0x80) !== 0) {
      // SSH wire protocol: if the high bit is set, prepend a zero byte
      // to ensure the number is interpreted as positive
      const paddedBytes = new Uint8Array(value.length + 1);
      paddedBytes[0] = 0x00;
      paddedBytes.set(value, 1);
      this.writeUint32(paddedBytes.length);
      this.writeBytes(paddedBytes);
    } else {
      this.writeUint32(value.length);
      this.writeBytes(value);
    }
  }

  /**
   * @deprecated Use writeMpInt(value, true) instead
   */
  writeMpIntSsh(value: Uint8Array): void {
    this.writeMpInt(value, true);
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
