// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Minimal contract that emits the same admin events as OpenZeppelin's
/// Ownable, AccessControl, Pausable and ERC-1967, for ownerwatch tests.
contract Admin {
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event Paused(address account);
    event Upgraded(address indexed implementation);

    address public owner;

    constructor() { owner = msg.sender; emit OwnershipTransferred(address(0), msg.sender); }

    function transferOwnership(address n) external { emit OwnershipTransferred(owner, n); owner = n; }
    function grantRole(bytes32 role, address a) external { emit RoleGranted(role, a, msg.sender); }
    function pause() external { emit Paused(msg.sender); }
    function upgradeTo(address impl) external { emit Upgraded(impl); }
}

contract NFT {
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    function transferFrom(address from, address to, uint256 id) external { emit Transfer(from, to, id); }
}

contract Multi {
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);
    event TransferBatch(address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values);
    function single(address from, address to, uint256 id, uint256 v) external { emit TransferSingle(msg.sender, from, to, id, v); }
    function batch(address from, address to, uint256[] calldata ids, uint256[] calldata vs) external { emit TransferBatch(msg.sender, from, to, ids, vs); }
}

contract Timelock {
    event CallScheduled(bytes32 indexed id, uint256 indexed index, address target, uint256 value, bytes data, bytes32 predecessor, uint256 delay);
    function schedule(address target, bytes calldata data) external {
        emit CallScheduled(keccak256(data), 0, target, 0, data, bytes32(0), 172800);
    }
}

contract LegacyTimelock {
    event NewDelay(uint256 indexed newDelay);
    event QueueTransaction(bytes32 indexed txHash, address indexed target, uint256 value, string signature, bytes data, uint256 eta);
    function setDelay(uint256 d) external { emit NewDelay(d); }
    function queue(address target, string calldata sig) external {
        emit QueueTransaction(keccak256(bytes(sig)), target, 0, sig, "", block.timestamp + 2 days);
    }
}

contract Gov {
    event ProposalCreated(uint256 proposalId, address proposer, address[] targets, uint256[] values, string[] signatures, bytes[] calldatas, uint256 voteStart, uint256 voteEnd, string description);
    event VotingDelaySet(uint256 oldVotingDelay, uint256 newVotingDelay);
    event SetApp(bytes32 indexed namespace, bytes32 indexed appId, address app);
    function propose(string calldata desc) external {
        address[] memory t = new address[](2); uint256[] memory v = new uint256[](2);
        string[] memory s = new string[](2); bytes[] memory c = new bytes[](2);
        emit ProposalCreated(42, msg.sender, t, v, s, c, 1, 2, desc);
    }
    function setDelay(uint256 d) external { emit VotingDelaySet(1, d); }
    function setApp(address a) external { emit SetApp(bytes32(uint256(1)), bytes32(uint256(2)), a); }
}

contract Token {
    event Transfer(address indexed from, address indexed to, uint256 value);
    function transfer(address to, uint256 v) external { emit Transfer(msg.sender, to, v); }
}
