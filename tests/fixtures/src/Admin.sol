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

contract RoleBox {
    mapping(bytes32 => mapping(address => bool)) public hasRole;
    constructor() { hasRole[bytes32(0)][msg.sender] = true; }
}

contract Proto {
    event PoolUpdated(address indexed oldAddress, address indexed newAddress);
    event SetCurator(address indexed newCurator);
    event SetCap(address indexed caller, bytes32 indexed id, uint256 cap);
    event Stopped();
    function poke(address a) external { emit PoolUpdated(address(0), a); emit SetCurator(a); emit SetCap(msg.sender, bytes32(uint256(9)), 5); emit Stopped(); }
}

contract Payloads {
    struct ExecutionAction { address target; bool withDelegateCall; uint8 accessLevel; uint256 value; string signature; bytes callData; }
    event PayloadCreated(uint40 indexed payloadId, address indexed creator, ExecutionAction[] actions, uint8 indexed maximumAccessLevelRequired);
    event PayloadQueued(uint40 payloadId);
    event PayloadExecuted(uint40 payloadId);
    event GuardianUpdated(address oldGuardian, address newGuardian);
    function poke(address a) external {
        ExecutionAction[] memory acts = new ExecutionAction[](2);
        acts[0] = ExecutionAction(a, true, 1, 0, "", abi.encodeWithSignature("execute()"));
        acts[1] = ExecutionAction(a, false, 1, 0, "setFee(uint256)", abi.encode(uint256(7)));
        emit PayloadCreated(42, msg.sender, acts, 1);
        emit PayloadQueued(42);
        emit PayloadExecuted(42);
        emit GuardianUpdated(address(0), a);
    }
}

contract SafeLike {
    event ExecutionFromModuleSuccess(address indexed module);
    event ExecutionSuccess(bytes32 txHash, uint256 payment);
    function viaModule() external { emit ExecutionFromModuleSuccess(msg.sender); }
    function exec() external { emit ExecutionSuccess(bytes32(uint256(7)), 0); }
}

contract Token {
    event Transfer(address indexed from, address indexed to, uint256 value);
    function transfer(address to, uint256 v) external { emit Transfer(msg.sender, to, v); }
}

/// Solady Timelock shape: minDelay(), no admin(), no owner().
contract SoladyTimelockLike {
    function minDelay() external pure returns (uint256) { return 86400; }
}

/// Custom Ownable timelock shape (Noon): delay() + owner(), no admin().
contract OwnedTimelockLike {
    address public owner = msg.sender;
    function delay() external pure returns (uint256) { return 172800; }
}

/// Factory-deployed ERC-1967 proxy (Solady ERC1967Factory shape): implementation slot set,
/// admin slot empty, the factory address embedded as an immutable, admin stored in the factory.
contract FactoryProxy {
    address public immutable factory;
    constructor(address impl) {
        factory = msg.sender;
        assembly { sstore(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, impl) }
    }
    function owner() external pure returns (address) { return address(0xBEEF); }
    function upgrade(address impl) external {
        require(msg.sender == factory, "only factory");
        assembly { sstore(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, impl) }
    }
}

contract ProxyFactoryLike {
    mapping(address => address) public adminOf;
    address public lastProxy;
    function deploy(address impl, address admin) external returns (address p) {
        p = address(new FactoryProxy(impl));
        adminOf[p] = admin;
        lastProxy = p;
    }
}

// Aave V3 patterns: Pool proxy with its admin (the PoolAddressesProvider) as an immutable, answering admin()
// only to the admin; the provider owned by an executor; the executor owned by a PayloadsController whose
// delay lives in its executor settings, per access level.
contract ImmutableAdminProxyLike {
    address internal immutable _admin;
    constructor(address impl) {
        _admin = msg.sender;
        assembly { sstore(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, impl) }
    }
    function admin() external returns (address) {
        if (msg.sender == _admin) return _admin;
        _delegate();
    }
    fallback() external payable { _delegate(); }
    function _delegate() internal {
        assembly {
            let impl := sload(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
}
contract AaveProviderLike {
    address public owner = msg.sender;
    address public lastProxy;
    function setOwner(address o) external { owner = o; }
    function deploy(address impl) external { lastProxy = address(new ImmutableAdminProxyLike(impl)); }
}
contract ExecutorLike {
    address public owner = msg.sender;
    function setOwner(address o) external { owner = o; }
}
contract PayloadsControllerLike {
    struct ExecutorConfig { address executor; uint40 delay; }
    mapping(uint8 => ExecutorConfig) internal _executors;
    address public owner = msg.sender;
    function setExecutor(uint8 level, address executor, uint40 delay) external { _executors[level] = ExecutorConfig(executor, delay); }
    function getExecutorSettingsByAccessControl(uint8 level) external view returns (ExecutorConfig memory) {
        return _executors[level];
    }
}
// AccessControl as it shows on-chain: grants and revokes emit the standard events; a protocol-specific role.
contract RoleLog {
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    mapping(bytes32 => mapping(address => bool)) public hasRole;
    bytes32 public constant POOL_ADMIN_ROLE = keccak256("POOL_ADMIN");
    constructor() { _grant(bytes32(0), msg.sender); }
    function grantRole(bytes32 role, address account) external { _grant(role, account); }
    function revokeRole(bytes32 role, address account) external {
        hasRole[role][account] = false;
        emit RoleRevoked(role, account, msg.sender);
    }
    function _grant(bytes32 role, address account) internal {
        hasRole[role][account] = true;
        emit RoleGranted(role, account, msg.sender);
    }
}
