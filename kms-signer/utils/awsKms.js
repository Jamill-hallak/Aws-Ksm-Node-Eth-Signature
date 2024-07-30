require('dotenv').config();
const AWS = require('aws-sdk');
const asn1 = require('asn1.js');
const elliptic = require('elliptic');
const ecCurve = new elliptic.ec('secp256k1');

AWS.config.update({ region: process.env.AWS_REGION });
const kms = new AWS.KMS();

const PublicKeyInfo = asn1.define('PublicKeyInfo', function() {
  this.seq().obj(
    this.key('algorithm').seq().obj(
      this.key('algorithm').objid(),
      this.key('parameters').objid()
    ),
    this.key('publicKey').bitstr()
  );
});

async function getPublicKeyDerBytesFromKMS(keyId) {
  try {
    const data = await kms.getPublicKey({ KeyId: keyId }).promise();
    return data.PublicKey;
  } catch (err) {
    throw new Error(`Cannot get public key from KMS for KeyId=${keyId}: ${err}`);
  }
}

async function getPubKey(keyId) {
  const pubKeyDerBytes = await getPublicKeyDerBytesFromKMS(keyId);
  const publicKeyInfo = PublicKeyInfo.decode(pubKeyDerBytes, 'der');
  const pubKeyBuffer = publicKeyInfo.publicKey.data;
  const key = ecCurve.keyFromPublic(pubKeyBuffer, 'hex');
  return key.getPublic();
}

module.exports = {
  getPublicKeyDerBytesFromKMS,
  getPubKey
};
