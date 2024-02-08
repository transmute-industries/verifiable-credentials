
import * as fixtures from "../../src/cr1/__fixtures__";

const { text, review } = fixtures

/*
Purpose of this test suite is not to cover every MUST/SHOULD 
but instead to cover the parts of the data model 
that are most likely to cause interoperability problems
*/

it("minimal VerifiableCredential", async () => {
  const validation = await review(fixtures.minimal_credential);
  expect(validation.warnings.length).toBe(0);
});
// We decline to implement validation for VerifiablePresentation
// because it is such an open ended data structure, we do not
// believe meaningful interoperability will be achieved with it
// it('minimal VerifiablePresentation', async () => {
//   const validation = await review(fixtures.minimal_credential)
//   expect(validation.warnings.length).toBe(0)
// })

// console.log(JSON.stringify(validation.warnings));

it("should warn about interoperability issues with decentralized identifiers", async () => {
  const validation = await review(fixtures.minimal_credential_with_dids);
  expect(validation.warnings).toEqual([
    {
      message: 'Identifier will not be well understood:  did:example:123',
      pointer: '/issuer',
      reference: 'https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#identifiers'
    },
    {
      message: 'Issuer MUST be a valid URL or an object containing an id property that is a valid URL',
      pointer: '/issuer',
      reference: 'https://www.w3.org/TR/vc-data-model-2.0/#issuer'
    },
    {
      message: 'Identifier will not be well understood:  did:example2:456',
      pointer: '/credentialSubject/id',
      reference: 'https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#identifiers'
    }
  ]);
});

it("should warn when identifier URLs are bad", async () => {
  const validation = await review(fixtures.minimal_credential_with_bad_urls);
  expect(validation.warnings).toEqual([
    {
      message: 'Identifier will not be well understood:  httttttttps://university.example/issuers/565049',
      pointer: '/issuer',
      reference: 'https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#identifiers'
    },
    {
      message: 'Issuer MUST be a valid URL or an object containing an id property that is a valid URL',
      pointer: '/issuer',
      reference: 'https://www.w3.org/TR/vc-data-model-2.0/#issuer'
    }
  ]);
});

it("should warn when context is broken", async () => {
  const validation = await review(fixtures.broken_context);
  expect(validation.warnings).toEqual([
    {
      message: "Credential will not be well understood, missing @context.",
      pointer: "/@context",
      reference:
        "https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#contexts",
    },
  ]);
});

// https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#identifiers
describe("Identifiers", () => {
  it("The id property MUST NOT have more than one value.", async () => {
    const validation = await review(
      text(`
"@context":
  - https://www.w3.org/ns/credentials/v2
type:
  - VerifiableCredential
issuer: https://university.example/issuers/565049
credentialSubject:
  id: 
    - https://university.example/issuers/1
    - https://university.example/issuers/2
    
`)
    );
    expect(validation.warnings).toEqual([
      {
        message: "The id property MUST NOT have more than one value.",
        pointer: "/credentialSubject/id/0",
        reference:
          "https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#identifiers",
      },
      {
        message: "The id property MUST NOT have more than one value.",
        pointer: "/credentialSubject/id/1",
        reference:
          "https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#identifiers",
      },
    ]);
  });
});

// https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#types
describe("Types", () => {
  it("type can be a string, or a URL", async () => {
    const validation = await review(
      text(`
"@context":
  - https://www.w3.org/ns/credentials/v2
type:
  - VerifiableCredential
  - https://example.gov/VerifiableCredential
issuer: https://university.example/issuers/565049
credentialSubject:
  id: https://university.example/issuers/1
`)
    );
    expect(validation.warnings).toEqual([]);
  });
});

// https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#names-and-descriptions
describe("Names and Descriptions", () => {
  it("name, and description need to be strings", async () => {
    const validation = await review(
      text(`
"@context":
  - https://www.w3.org/ns/credentials/v2
type:
  - VerifiableCredential
issuer: 
  id: https://university.example/issuers/565049
  name: 42
  description: false
credentialSubject:
  id: https://university.example/issuers/1
`)
    );
    expect(validation.warnings).toEqual([
      {
        message: "Names must be strings",
        pointer: "/issuer/name",
        reference:
          "https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#names-and-descriptions",
      },
      {
        message: "Description must be strings",
        pointer: "/issuer/description",
        reference:
          "https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#names-and-descriptions",
      },
    ]);
  });
});

// https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#credential-subject
describe("Credential Subject", () => {
  it("it can be an array", async () => {
    const validation = await review(
      text(`
"@context":
  - https://www.w3.org/ns/credentials/v2
type:
  - VerifiableCredential
issuer: 
  id: https://university.example/issuers/565049
credentialSubject:
  - id: https://university.example/issuers/1
  - id: https://university.example/issuers/2
`)
    );
    expect(validation.warnings).toEqual([]);
  });
});

// https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#issuer
// MUST BE: URL, or Object with ID that is URL
describe("Issuer", () => {
  it("can be object with id as url", async  () => {
    const validation = await review(
      text(`
"@context":
  - https://www.w3.org/ns/credentials/v2
type:
  - VerifiableCredential
issuer: 
  id: https://university.example/issuers/565049
credentialSubject:
  - id: https://university.example/issuers/1
  - id: https://university.example/issuers/2
`)
    );
    expect(validation.warnings).toEqual([]);
  })

  it("can be url", async  () => {
    const validation = await review(
      text(`
"@context":
  - https://www.w3.org/ns/credentials/v2
type:
  - VerifiableCredential
issuer: https://university.example/issuers/565049
credentialSubject:
  - id: https://university.example/issuers/1
  - id: https://university.example/issuers/2
`)
    );
    expect(validation.warnings).toEqual([]);
  })

  it("gives warning if issuer not valid url", async  () => {
    const validation = await review(
      text(`
"@context":
  - https://www.w3.org/ns/credentials/v2
type:
  - VerifiableCredential
issuer: test
credentialSubject:
  - id: https://university.example/issuers/1
  - id: https://university.example/issuers/2
`)
    );
    expect(validation.warnings[1]).toStrictEqual({
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      message: `Issuer MUST be a valid URL or an object containing an id property that is a valid URL`,
      pointer: '/issuer',
      reference: 'https://www.w3.org/TR/vc-data-model-2.0/#issuer'
    });
  })

  it("gives warning if issuer.id not valid url", async  () => {
    const validation = await review(
      text(`
"@context":
  - https://www.w3.org/ns/credentials/v2
type:
  - VerifiableCredential
issuer: 
  id: test
credentialSubject:
  - id: https://university.example/issuers/1
  - id: https://university.example/issuers/2
`)
    );
    expect(validation.warnings[1]).toStrictEqual({
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      message: `Issuer MUST be a valid URL or an object containing an id property that is a valid URL`,
      pointer: '/issuer/id',
      reference: 'https://www.w3.org/TR/vc-data-model-2.0/#issuer'
    });
  })
});

// https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#presentations-0
describe("Presentations", () => {
  describe("verifiableCredential", () => {
    it("can be an array of enveloped credentials and credentials", async  () => {
      const validation = await review(
        text(`
  "@context":
    - https://www.w3.org/ns/credentials/v2
  type:
    - VerifiablePresentation
  holder: 
    id: https://university.example/issuers/565049
  verifiableCredential:
    - "@context": https://www.w3.org/ns/credentials/v2
      id: data:application/vc+ld+json+sd-jwt;QzVjV...RMjU
      type: EnvelopedVerifiableCredential
    - "@context":
        - https://www.w3.org/ns/credentials/v2
      type:
        - VerifiableCredential
      issuer: 
        id: https://university.example/issuers/565049
      credentialSubject:
        - id: https://university.example/issuers/1
        - id: https://university.example/issuers/2
  `)
      );
      expect(validation.warnings).toEqual([{
        message: 'Identifier will not be well understood:  data:application/vc+ld+json+sd-jwt;QzVjV...RMjU',
        pointer: '/verifiableCredential/0/id',
        reference: 'https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#identifiers'
      }]);
    })

    it("warns when non-object value is used", async  () => {
      const validation = await review(
        text(`
  "@context":
    - https://www.w3.org/ns/credentials/v2
  type:
    - VerifiablePresentation
  holder: 
    id: https://university.example/issuers/565049
  verifiableCredential:
    - badValue
  `)
      );

      expect(validation.warnings).toEqual([{
        message: 'verifiableCredential MUST NOT be non-object values such as numbers, strings, or URLs',
        pointer: '/verifiableCredential/0',
        reference: 'https://www.w3.org/TR/vc-data-model-2.0/#presentations-0'
      }]);
    })

    it("warns when enveloped credential id is not valid", async  () => {
      const validation = await review(
        text(`
  "@context":
    - https://www.w3.org/ns/credentials/v2
  type:
    - VerifiablePresentation
  holder: 
    id: https://university.example/issuers/565049
  verifiableCredential:
    - "@context": https://www.w3.org/ns/credentials/v2
      id: QzVjV...RMjU
      type: EnvelopedVerifiableCredential
    - "@context":
        - https://www.w3.org/ns/credentials/v2
      type:
        - VerifiableCredential
      issuer: 
        id: https://university.example/issuers/565049
      credentialSubject:
        - id: https://university.example/issuers/1
        - id: https://university.example/issuers/2
  `)
      );

      expect(validation.warnings).toEqual([{
        message: 'Identifier will not be well understood:  QzVjV...RMjU',
        pointer: '/verifiableCredential/0/id',
        reference: 'https://www.w3.org/TR/2024/CRD-vc-data-model-2.0-20240205/#identifiers'
      },
      {
        message: 'verifiableCredential id value of the object MUST be a data: URL',
        pointer: '/verifiableCredential/0/id',
        reference: 'https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-credentials'
      }]);
    })
  });
  describe("holder", () => {
    it("can be object with id as url", async  () => {
      const validation = await review(
        text(`
  "@context":
    - https://www.w3.org/ns/credentials/v2
  type:
    - VerifiablePresentation
  holder: 
    id: https://university.example/issuers/565049
  `)
      );
      expect(validation.warnings).toEqual([]);
    })
  
    it("can be url", async  () => {
      const validation = await review(
        text(`
  "@context":
    - https://www.w3.org/ns/credentials/v2
  type:
    - VerifiablePresentation
  holder: https://university.example/issuers/565049
  `)
      );
      expect(validation.warnings).toEqual([]);
    })
  
    it("gives warning if issuer not valid url", async  () => {
      const validation = await review(
        text(`
  "@context":
    - https://www.w3.org/ns/credentials/v2
  type:
    - VerifiablePresentation
  holder: test
  `)
      );
      expect(validation.warnings[0]).toStrictEqual({
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        message: `Holder MUST be a valid URL or an object containing an id property that is a valid URL`,
        pointer: '/holder',
        reference: 'https://www.w3.org/TR/vc-data-model-2.0/#presentations-0'
      });
    })
  
    it("gives warning if issuer.id not valid url", async  () => {
      const validation = await review(
        text(`
  "@context":
    - https://www.w3.org/ns/credentials/v2
  type:
    - VerifiablePresentation
  holder: 
    id: test
  `)
      );
      expect(validation.warnings[1]).toStrictEqual({
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        message: `Holder MUST be a valid URL or an object containing an id property that is a valid URL`,
        pointer: '/holder/id',
        reference: 'https://www.w3.org/TR/vc-data-model-2.0/#presentations-0'
      });
    })
  });
  
});

// it.todo('data model tests')
// it.todo('data times tests')
// it.todo('urls times tests')
// it.todo('data urls tests')
