require('dotenv').config();
const { getPubKey, signEthereumMessage } = require('./lib/kmsSigner');
const { BN, keccak256, bufferToHex } = require('ethereumjs-util');
const { getAddress } = require('./utils/ethereum');

(async () => {
  const keyID = process.env.AWS_KMS_KEY_ID;
  if (!keyID) {
    throw new Error('AWS_KMS_KEY_ID not set in .env file');
  }

  try {
    const pubKey = await getPubKey(keyID);
    // console.log('Public Key:', pubKey); // Print the public key

    const address = getAddress(pubKey);
    console.log('Authorized Signer Address:', address);

    const authorizedSigner = address;
    const landId = new BN(12);
    const founder = '0x1234567890abcdef1234567890abcdef12345678';
    const nonce = Buffer.from('04973370d5bca7584e204448ecf9a6bf820ef92ce7330fcc00000190f91b68ae', 'hex');

    const authorizedSignerBytes = Buffer.from(authorizedSigner.slice(2), 'hex');
    const landIdBytes = Buffer.alloc(32);
    landIdBytes.writeUInt32BE(landId.toNumber(), 28);
    const founderBytes = Buffer.from(founder.slice(2), 'hex');

    const message = Buffer.concat([authorizedSignerBytes, landIdBytes, founderBytes, nonce]);
    const messageHash = keccak256(message);
    const prefix = Buffer.from('\x19Ethereum Signed Message:\n32');
    const prefixedMessage = Buffer.concat([prefix, messageHash]);
    const ethSignedMessageHash = keccak256(prefixedMessage);

    const signature = await signEthereumMessage(keyID, ethSignedMessageHash);
    console.log('Signature:', signature); // Print the signature
  } catch (err) {
    console.error('Error:', err.message);
  }
})();
