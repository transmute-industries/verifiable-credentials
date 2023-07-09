/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */

// Modified for TypeScript by Orie Steele

export function isNumber(value: number, name: string) {
  if (typeof value !== 'number') {
    throw new TypeError(`"${name}" must be number.`)
  }
}

export function isPositiveInteger(value: number, name: string) {
  if (!(Number.isInteger(value) && value > 0)) {
    throw new TypeError(`"${name}" must be a positive integer.`)
  }
}

export function isString(value: string, name: string) {
  if (typeof value !== 'string') {
    throw new TypeError(`"${name}" must be a string.`)
  }
}

export function isBoolean(value: boolean, name: string) {
  if (typeof value !== 'boolean') {
    throw new TypeError(`"${name}" must be a boolean.`)
  }
}

export function isNonNegativeInteger(value: number, name: string) {
  if (!(Number.isInteger(value) && value >= 0)) {
    throw new TypeError(`"${name}" must be a non-negative integer.`)
  }
}

export function isUint8Array(value: Uint8Array, name: string) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`"${name}" must be a Uint8Array.`)
  }
}
