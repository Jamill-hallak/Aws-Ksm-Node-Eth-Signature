const { keccak256, bufferToHex, pubToAddress, ecrecover } = require('ethereumjs-util');
const elliptic = require('elliptic');
const ecCurve = new elliptic.ec('secp256k1');

function getAddress(pubKey) {
  const pubBytes = Buffer.concat([
    Buffer.from([0x04]),
    pubKey.getX().toArrayLike(Buffer, 'be', 32),
    pubKey.getY().toArrayLike(Buffer, 'be', 32)
  ]);
  const addressBuffer = pubToAddress(pubBytes.slice(1), true);
  return bufferToHex(addressBuffer);
}

function recoverAddress(ethSignedMessageHash, r, s, pubKey) {
  let v = 27;
  const pubAddress = getAddress(pubKey);

  for (let i = 0; i < 2; i++) {
    const vCandidate = 27 + i;
    try {
      const recoveredPubKey = ecrecover(ethSignedMessageHash, vCandidate, r.toArrayLike(Buffer, 'be', 32), s.toArrayLike(Buffer, 'be', 32));
      const recoveredAddress = bufferToHex(pubToAddress(recoveredPubKey));
      if (pubAddress === recoveredAddress) {
        v = vCandidate;
        break;
      }
    } catch (err) {
      // Recovery attempt failed, continue
    }
  }

  return v;
}

module.exports = {
  keccak256,
  getAddress,
  recoverAddress
};
