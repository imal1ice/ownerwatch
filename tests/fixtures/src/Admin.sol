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

contract Token {
    event Transfer(address indexed from, address indexed to, uint256 value);
    function transfer(address to, uint256 v) external { emit Transfer(msg.sender, to, v); }
}
