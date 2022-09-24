const moment = require('moment');

const jws = require('./jws');

const encode = (presentation, nonce, aud) => {
  const p = JSON.parse(JSON.stringify(presentation));
  const header = {typ: 'JWT'};

  const payload = {vp: p};
  // required
  payload.iss = p.holder.id ? p.holder.id : p.holder;
  payload.sub = p.holder.id ? p.holder.id : p.holder;

  payload.aud = aud;
  if (nonce) {
    payload.nonce = nonce;
  } else {
    throw new Error(
        // eslint-disable-next-line max-len
        'Nonce is required by verifiable presentations to protect against replay attacks.',
    );
  }

  payload.nbf = moment().valueOf();
  payload.iat = moment().valueOf();
  payload.exp = moment().add(2, 'minutes').valueOf();

  if (p.id) {
    payload.jti = p.id;
  }

  return JSON.parse(JSON.stringify({header, payload}));
};

const secure = async ({presentation, privateKey, nonce, aud}) => {
  const encoding = encode(presentation, nonce, aud);
  const {header, payload} = encoding;
  const message = new TextEncoder().encode(JSON.stringify(payload));
  return jws.signWithKey(message, privateKey, {
    ...header,
    kid: privateKey.kid, // how else to know which key to use to verify?
  });
};

const verify = async ({
  verifiablePresentation,
  nonce,
  publicKey,
  dereferencer,
}) => {
  try {
    if (!publicKey) {
      const header = JSON.parse(
          // eslint-disable-next-line max-len
          Buffer.from(verifiablePresentation.split('.')[0], 'base64').toString(),
      );
      publicKey = await dereferencer(header.kid);
    }
    const result = await jws.verifyWithKey(verifiablePresentation, publicKey);
    const payload = JSON.parse(result.payload.toString());
    const presentation = payload.vp;

    if (nonce !== payload.nonce) {
      throw new Error('Nonce does not match');
    }

    return {
      verified: true,
      presentation,
    };
  } catch (e) {
    // console.error(e);
    return {verified: false};
  }
};

module.exports = {
  encode,
  secure,
  verify,
};
