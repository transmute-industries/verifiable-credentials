const Ajv = require('ajv/dist/2020');
const ajv = new Ajv({strictTuples: false});

describe('JSON Schema', () => {
  describe('basic', () => {
    const schema = {
      type: 'object',
      properties: {
        foo: {type: 'integer'},
        bar: {type: 'string'},
      },
      required: ['foo'],
      additionalProperties: false,
    };

    it('valid', () => {
      const data = {foo: 1, bar: 'abc'};
      const valid = ajv.validate(schema, data);
      expect(valid).toBe(true);
    });

    it('invalid', () => {
      const data = {
        // missing required property
        // foo: 1,
        bar: 'abc',
      };
      const valid = ajv.validate(schema, data);
      expect(valid).toBe(false);
    });
  });

  describe('array ordering', () => {
    it('valid', () => {
      const valid = ajv.validate(
          {
            type: 'array',
            minItems: 2,
            prefixItems: [{type: 'integer'}, {type: 'integer'}],
            items: {type: 'string'},
          },
          [1, 2, 'abc'],
      );
      expect(valid).toBe(true);
    });
  });
});
