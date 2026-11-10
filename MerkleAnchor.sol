// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * ASTRA — MerkleAnchor Smart Contract
 *
 * Instead of writing every threat record on-chain (expensive), ASTRA hashes
 * each record into a Merkle tree off-chain and anchors ONLY the 32-byte root
 * of each batch here. Any single record can later be proven to belong to a
 * batch with a logarithmic-size Merkle proof, so tamper-evidence is kept while
 * gas cost per record drops roughly by the batch size.
 *
 * Hashing convention (OpenZeppelin-compatible "sorted pair" tree):
 *     parent = keccak256(min(a, b) ++ max(a, b))
 * so proofs need no left/right direction flags.
 */
contract MerkleAnchor {

    struct Batch {
        bytes32 root;        // Merkle root of the batch
        uint64  leafCount;   // number of records committed by this root
        uint64  timestamp;   // block timestamp of anchoring
    }

    Batch[] private batches;
    address public owner;

    event BatchAnchored(
        uint256 indexed batchId,
        bytes32 root,
        uint64  leafCount,
        uint64  timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// Anchor the Merkle root of a batch of threat records.
    function anchorBatch(bytes32 root, uint64 leafCount)
        external
        onlyOwner
        returns (uint256 batchId)
    {
        require(root != bytes32(0), "Empty root");
        require(leafCount > 0, "Empty batch");

        batchId = batches.length;
        batches.push(Batch(root, leafCount, uint64(block.timestamp)));

        emit BatchAnchored(batchId, root, leafCount, uint64(block.timestamp));
    }

    function getBatch(uint256 batchId)
        external
        view
        returns (bytes32 root, uint64 leafCount, uint64 timestamp)
    {
        require(batchId < batches.length, "Batch not found");
        Batch storage b = batches[batchId];
        return (b.root, b.leafCount, b.timestamp);
    }

    function totalBatches() external view returns (uint256) {
        return batches.length;
    }

    /// Verify on-chain that `leaf` is part of batch `batchId`.
    function verify(uint256 batchId, bytes32 leaf, bytes32[] calldata proof)
        external
        view
        returns (bool)
    {
        require(batchId < batches.length, "Batch not found");
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            computed = computed <= p
                ? keccak256(abi.encodePacked(computed, p))
                : keccak256(abi.encodePacked(p, computed));
        }
        return computed == batches[batchId].root;
    }
}
