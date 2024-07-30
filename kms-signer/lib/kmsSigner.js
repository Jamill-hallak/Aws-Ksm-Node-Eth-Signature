const { BN } = require('bn.js');
const { getPubKey, getPublicKeyDerBytesFromKMS } = require('../utils/awsKms');
const { keccak256, getAddress, recoverAddress } = require('../utils/ethereum');

const awsKmsSignOperationMessageType = 'DIGEST';
const awsKmsSignOperationSigningAlgorithm = 'ECDSA_SHA_256';

const secp256k1N = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);
const secp256k1HalfN = secp256k1N.div(new BN(2));

async function signEthereumMessage(keyId, ethSignedMessageHash) {
  const signParams = {
    KeyId: keyId,
    Message: ethSignedMessageHash,
    SigningAlgorithm: awsKmsSignOperationSigningAlgorithm,
    MessageType: awsKmsSignOperationMessageType,
  };

  try {
    const data = await kms.sign(signParams).promise();
    const derSignature = data.Signature;

    const decodedSignature = EcdsaSigAsnParse.decode(derSignature, 'der');
    const r = decodedSignature.r;
    let s = decodedSignature.s;

    if (s.cmp(secp256k1HalfN) > 0) {
      s = secp256k1N.sub(s);
    }

    const rHex = r.toString('hex').padStart(64, '0');
    const sHex = s.toString('hex').padStart(64, '0');

    const pubKey = await getPubKey(keyId);
    const v = recoverAddress(ethSignedMessageHash, r, s, pubKey);

    return `0x${rHex}${sHex}${v.toString(16).padStart(2, '0')}`;
  } catch (err) {
    throw new Error(`Error signing message: ${err}`);
  }
}

module.exports = {
  getPubKey,
  signEthereumMessage
};
