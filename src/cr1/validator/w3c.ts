import { ValidationResult } from "../types";

import pointer from 'json-pointer'

const identifierAlias = [
  '/issuer'
]

const allowedProtocols = ['https']

const isPointerToIdentifier = (pointer: string) => {
  return pointer.endsWith('/id') || identifierAlias.includes(pointer)
}


const stringIsAValidUrl = (s: string, protocols: string[]) => {
  try {
    const parsed = new URL(s);
    return protocols
      ? parsed.protocol
        ? protocols.map((x: any) => `${x.toLowerCase()}:`).includes(parsed.protocol)
        : false
      : true;
  } catch (err) {
    return false;
  }
};

// https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#identifiers
const identifiers = (result: ValidationResult, pointer: string, value: any) => {
  if (isPointerToIdentifier(pointer)) {
    const identifierAllowed = stringIsAValidUrl(value, allowedProtocols)
    if (!identifierAllowed) {
      result.warnings.push({
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        message: `Identifier will not be well understood:  ${value}`,
        pointer,
        reference: 'https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#identifiers'
      })
    }
  }
  if (pointer.includes('id/')) {
    result.warnings.push({
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      message: `The id property MUST NOT have more than one value.`,
      pointer,
      reference: 'https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#identifiers'
    })
  }
}

// https://www.w3.org/TR/vc-data-model-2.0/#issuer
const issuer = (result: ValidationResult, pointer: string, value: any) => {
  if (pointer.endsWith('/issuer') || pointer.endsWith('/issuer/id')) {
    const issuerAllowed = stringIsAValidUrl(value, allowedProtocols)
    if (!issuerAllowed) {
      result.warnings.push({
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        message: `Issuer MUST be a valid URL or an object containing an id property that is a valid URL`,
        pointer,
        reference: 'https://www.w3.org/TR/vc-data-model-2.0/#issuer'
      })
    }
  }
}

// https://www.w3.org/TR/vc-data-model-2.0/#presentations-0
const holder = (result: ValidationResult, pointer: string, value: any) => {
  if (pointer.endsWith('/holder') || pointer.endsWith('/holder/id')) {
    const issuerAllowed = stringIsAValidUrl(value, allowedProtocols)
    if (!issuerAllowed) {
      result.warnings.push({
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        message: `Holder MUST be a valid URL or an object containing an id property that is a valid URL`,
        pointer,
        reference: 'https://www.w3.org/TR/vc-data-model-2.0/#presentations-0'
      })
    }
  }
}

// https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#types
const types = (result: ValidationResult, pointer: string, value: any) => {
  // I'm not writing a test for:
  // The value of the type property MUST be,
  // or map to (through interpretation of the @context property), one or more URLs.
}

// https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#names-and-descriptions
const names_and_descriptions = (result: ValidationResult, pointer: string, value: any) => {
  if (pointer.endsWith('/name') && typeof value !== 'string') {
    result.warnings.push({
      message: `Names must be strings`,
      pointer,
      reference: 'https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#names-and-descriptions'
    })
  }
  if (pointer.endsWith('/description') && typeof value !== 'string') {
    result.warnings.push({
      message: `Description must be strings`,
      pointer,
      reference: 'https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#names-and-descriptions'
    })
  }
  // I am not writing a test for "language objects" as described in 
  // https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#language-and-base-direction
}


// https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#credential-subject

export const conformance = (result: ValidationResult) => {

  const dict = pointer.dict(result.content)
  const pointers = Object.keys(dict)

  if (!result.content['@context']) {
    result.warnings.push({
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      message: `Credential will not be well understood, missing @context.`,
      pointer: '/@context',
      reference: 'https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#contexts'
    })
  }

  for (const pointer of pointers) {
    const value = dict[pointer]
    identifiers(result, pointer, value)
    types(result, pointer, value)
    names_and_descriptions(result, pointer, value)
    issuer(result, pointer, value)
    holder(result, pointer, value)
  }

  return result
}