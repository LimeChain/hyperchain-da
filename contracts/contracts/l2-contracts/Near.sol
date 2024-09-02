// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

// solhint-disable gas-custom-errors, reason-string

import {IL2DAValidator} from "./interfaces/IL2DAValidator.sol";
//TODO: Is this how you import the contract properly?
import "../../lib/era-contracts/l2-contracts/contracts/data-availability/StateDiffL2DAValidator.sol";
import {EfficientCall} from "../../lib/era-contracts/system-contracts/contracts/libraries/EfficientCall.sol";

/// NEAR DA validator. It will publish inclusion data that would allow to verify the inclusion.
contract NearL2DAValidator is IL2DAValidator, StateDiffL2DAValidator {
    function validatePubdata(
    // The rolling hash of the user L2->L1 logs.
        bytes32,
    // The root hash of the user L2->L1 logs.
        bytes32,
    // The chained hash of the L2->L1 messages
        bytes32 _chainedMessagesHash,
    // The chained hash of uncompressed bytecodes sent to L1
        bytes32 _chainedBytecodesHash,
    // Operator data, that is related to the DA itself
        bytes calldata _totalL2ToL1PubdataAndStateDiffs
    ) external returns (bytes32 outputHash) {
        (bytes32 stateDiffHash, bytes calldata _totalPubdata, bytes calldata leftover) = _produceStateDiffPubdata(
            _chainedMessagesHash,
            _chainedBytecodesHash,
            _totalL2ToL1PubdataAndStateDiffs
        );

        /// Check for calldata strict format
        require(leftover.length == 0, "Extra data found");

        // The preimage under the hash `outputHash` is expected to be in the following format:
        // - First 32 bytes are the hash of the uncompressed state diff.
        // - Then, there is a 32-byte hash of the full pubdata.
        // - Then, there is the 1-byte number of blobs published.
        // - Then, there are linear hashes of the published blobs, 32 bytes each.

        bytes32[] memory blobLinearHashes = PUBDATA_CHUNK_PUBLISHER.chunkPubdataToBlobs(_totalPubdata);

        outputHash = keccak256(
            abi.encodePacked(
                stateDiffHash,
                EfficientCall.keccak(_totalPubdata),
                SafeCast.toUint8(blobLinearHashes.length),
                blobLinearHashes
            )
        );
    }
}
