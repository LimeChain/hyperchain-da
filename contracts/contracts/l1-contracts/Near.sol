// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

// solhint-disable gas-custom-errors, reason-string

import {IL1DAValidator, L1DAValidatorOutput} from "../l1-contracts/interfaces/IL1DAValidator.sol";
import {BlobstreamX} from "blobstreamx/BlobstreamX.sol";
import "./interfaces/INearProver.sol";

// the state diff hash, hash of pubdata + the number of blobs.
uint256 constant BLOB_DATA_OFFSET = 65;

contract NearDAValidator is IL1DAValidator {
    INearProver public nearProver;

    constructor(address _nearProver) {
        nearProver = INearProver(_nearProver);
    }

    /// @inheritdoc IL1DAValidator
    function checkDA(
        uint256, // _chainId
        bytes32 _l2DAValidatorOutputHash,
        bytes calldata _operatorDAInput,
        uint256 _maxBlobsSupported
    ) external view returns (L1DAValidatorOutput memory output) {
        // The preimage under the hash `_l2DAValidatorOutputHash` is expected to be in the following format:
        // - First 32 bytes are the hash of the uncompressed state diff.
        // - Then, there is a 32-byte hash of the full pubdata.
        // - Then, there is the 1-byte number of blobs published.
        // - Then, there are linear hashes of the published blobs, 32 bytes each.

        // Check that it accommodates enough pubdata for the state diff hash, hash of pubdata + the number of blobs.
        // require(_operatorDAInput.length >= BLOB_DATA_OFFSET, "too small");

        bytes32 stateDiffHash = bytes32(_operatorDAInput[:32]);
        bytes32 fullPubdataHash = bytes32(_operatorDAInput[32:64]);
        uint256 blobsProvided = uint256(uint8(_operatorDAInput[64]));

        // require(blobsProvided <= _maxBlobsSupported, "invalid number of blobs");

        // Note that the API of the contract requires that the returned blobs linear hashes have length of
        // the `_maxBlobsSupported`
        bytes32[] memory blobsLinearHashes = new bytes32[](_maxBlobsSupported);

        // require(_operatorDAInput.length >= BLOB_DATA_OFFSET + 32 * blobsProvided, "invalid blobs hashes");

        assembly {
        // The pointer to the allocated memory above. We skip 32 bytes to avoid overwriting the length.
            let blobsPtr := add(blobsLinearHashes, 0x20)
            let inputPtr := add(_operatorDAInput.offset, BLOB_DATA_OFFSET)
            calldatacopy(blobsPtr, inputPtr, mul(blobsProvided, 32))
        }

        uint256 ptr = BLOB_DATA_OFFSET + 32 * blobsProvided;

        // Now, we need to double check that the provided input was indeed returned by the L2 DA validator.
        // require(keccak256(_operatorDAInput[:ptr]) == _l2DAValidatorOutputHash, "invalid l2 DA output hash");

        // The rest of the output was provided specifically by the operator
        bytes calldata l1DaInput = _operatorDAInput[ptr:];

        // TODO: Incorporate outputHash as a leaf node in the proofs
        // Alternative option: change proveOutcome parameters to accept leaf node.
        bool isValid = nearProver.proveOutcome(l1DaInput);

        // require(isValid, "Near on-chain proof verification failed");

        output.stateDiffHash = stateDiffHash;
        output.blobsLinearHashes = blobsLinearHashes;
        output.blobsOpeningCommitments = blobCommitments;
    }
}
