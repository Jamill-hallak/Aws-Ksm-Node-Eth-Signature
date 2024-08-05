// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract Verifier {
    using ECDSA for bytes32;

    address public authorizedSigner;

    constructor(address _authorizedSigner) {
        authorizedSigner = _authorizedSigner;
    }
//Note : add "0x" prefix to nonce if it not start with it 
    function verifySignature(uint256 landId, address founder, bytes32 nonce, bytes memory signature) public view returns (bool, bytes32, bytes32) {
        bytes32 message = keccak256(abi.encodePacked(authorizedSigner, landId, founder, nonce));
        bytes32 ethSignedMessage = MessageHashUtils.toEthSignedMessageHash(message);
        bool isValid = ECDSA.recover(ethSignedMessage, signature) == authorizedSigner;
        return (isValid, message, ethSignedMessage);
    }
}
