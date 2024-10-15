/*!
 * Copyright (c) 2020-2023 Digital Bazaar, Inc. All rights reserved.
 */

// Modified for TypeScript by Orie Steele

import { gzip, ungzip } from 'pako'
import { base64url } from 'jose'

import * as assert from './assertions'

export type BitstringConstructorArguments = {
  length?: number
  buffer?: Uint8Array
  leftToRightIndexing?: boolean
  littleEndianBits?: boolean
}

export type EncodedBits = {
  encoded: string
}

export type CompressedBits = {
  compressed: Uint8Array
}

export class Bitstring {
  public length: number
  public bits: Uint8Array
  public leftToRightIndexing: boolean
  /**
   * Creates a new Bitstring  instance.
   *
   * @param {object} options - The options to use.
   * @param {number} [options.length] - The length of the bitstring in bits;
   *   either this or `buffer` must be given, but not both.
   * @param {Uint8Array} [options.buffer] - The bitstring as a buffer of bytes
   *   where the bytes are always in big endian order (left most byte or most
   *   significant byte in the buffer will be the least significant and lowest
   *   index byte in the bitstring) and where the bit order
   *   is also little endian by default but may be specified as big endian
   *   by passing `leftToRightIndexing: false`; either this parameter or
   *   `length` must be given but not both.
   * @param {boolean} [options.leftToRightIndexing=true] - Whether the bit
   *   order (NOT the byte order, which is *always* first byte in the buffer is
   *   the first byte-index into the bitstring, i.e., left to right) is left to
   *   right or not; the default is left to right, which matches what the byte
   *   order always is and, specifically, means that `0x80` or `0b1000000`
   *   means the first bit index is set in a given byte.
   * @param {boolean} [options.littleEndianBits] - Deprecated; use
   *   `leftToRightIndexing` instead.
   */
  constructor({
    length,
    buffer,
    leftToRightIndexing,
    littleEndianBits,
  }: BitstringConstructorArguments = {}) {
    if (length && buffer) {
      throw new Error('Only one of "length" or "buffer" must be given.')
    }
    if (length !== undefined) {
      assert.isPositiveInteger(length, 'length')
    } else {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      assert.isUint8Array(buffer as any, 'buffer')
    }
    // backwards compatibility for deprecated name `littleEndianBits`
    if (littleEndianBits !== undefined) {
      if (leftToRightIndexing !== undefined) {
        throw new Error(
          'Using both "littleEndianBits" and "leftToRightIndexing" ' +
          'is not allowed.',
        )
      }
      assert.isBoolean(littleEndianBits, 'littleEndianBits')
      leftToRightIndexing = littleEndianBits
    }
    if (leftToRightIndexing === undefined) {
      leftToRightIndexing = true
    } else {
      assert.isBoolean(leftToRightIndexing, 'leftToRightIndexing')
    }
    if (length) {
      this.bits = new Uint8Array(Math.ceil(length / 8))
      this.length = length
    } else {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      this.bits = new Uint8Array((buffer as any).buffer)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      this.length = (buffer as any).length * 8
    }
    this.leftToRightIndexing = leftToRightIndexing
  }

  set(position: number, on: boolean) {
    assert.isNumber(position, 'position')
    assert.isBoolean(on, 'on')
    const { length, leftToRightIndexing } = this
    const { index, bit } = _parsePosition(position, length, leftToRightIndexing)
    if (on) {
      this.bits[index] |= bit
    } else {
      this.bits[index] &= 0xff ^ bit
    }
  }

  get(position: number) {
    assert.isNumber(position, 'position')
    const { length, leftToRightIndexing } = this
    const { index, bit } = _parsePosition(position, length, leftToRightIndexing)
    const actualBitSet = this.bits[index] & bit % 8
    // Let bitstring be a list of bits with a minimum size of 16KB, where each bit is initialized to 0 (zero).
    // ....
    // When a single bit specifies a status, such as "revoked" or "suspended", 
    // then that status is expected to be true when the bit is set (1) and false when unset (0).
    if (actualBitSet === 1) {
      return true
    }
    if (actualBitSet === 0) {
      return false
    }
    throw new Error('Invalid bit')
  }


  async encodeBits() {
    return base64url.encode(gzip(this.bits))
  }

  static decodeBits({ encoded }: EncodedBits): Uint8Array {
    assert.isString(encoded, 'encoded')
    return ungzip(base64url.decode(encoded))
  }

  async compressBits() {
    return gzip(this.bits)
  }

  static async uncompressBits({ compressed }: CompressedBits) {
    assert.isUint8Array(compressed, 'compressed')
    return ungzip(compressed)
  }
}

function _parsePosition(
  position: number,
  length: number,
  leftToRightIndexing: boolean,
) {
  assert.isNonNegativeInteger(position, 'position')
  assert.isPositiveInteger(length, 'length')
  assert.isBoolean(leftToRightIndexing, 'leftToRightIndexing')

  if (position >= length) {
    throw new Error(`Position "${position}" is out of range "0-${length - 1}".`)
  }
  const index = Math.floor(position / 8)
  const rem = position % 8
  const shift = leftToRightIndexing ? 7 - rem : rem

  // When a single bit specifies a status, such as "revoked" or "suspended", 
  // then that status is expected to be true when the bit is set (1) and false when unset (0).
  const bit = (1 << shift)
  // the real bit value is bit % 8
  return { index, bit }
}
