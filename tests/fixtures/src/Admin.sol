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
    function propose(bytes32, bytes calldata, uint256) external {}
}

/// Custom Ownable timelock shape (Noon): delay() + owner(), no admin().
contract OwnedTimelockLike {
    address public owner = msg.sender;
    function delay() external pure returns (uint256) { return 172800; }
    function MIN_DELAY() external pure returns (uint256) { return 3600; }
}

/// Factory-deployed ERC-1967 proxy (Solady ERC1967Factory shape): implementation slot set,
/// admin slot empty, the factory address embedded as an immutable, admin stored in the factory.
contract FactoryProxy {
    address public immutable factory;
    constructor(address impl) {
        factory = msg.sender;
        assembly { sstore(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, impl) }
    }
    function owner() external pure returns (address) { return address(uint160(uint256(keccak256("owner")))); }
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
// Governance patterns of large protocols: an Aragon app (Lido), a Balancer-style vault with an enumerable
// AccessControl authorizer, a factory with upgradeAdmin() (Euler), a Curve-style admin with dao()/emergency(),
// and Maker/Sky wards with a DSPause-like timelock behind the pause proxy (Spark).
contract AragonAppLike {
    address public kernel = address(uint160(uint256(keccak256("kernel"))));
    function appId() external pure returns (bytes32) { return keccak256("lido"); }
}
contract EnumerableAuthorizer {
    address[] internal admins;
    constructor() { admins.push(msg.sender); }
    function hasRole(bytes32 role, address who) external view returns (bool) { return role == bytes32(0) && who == admins[0]; }
    function getRoleMemberCount(bytes32 role) external view returns (uint256) { return role == bytes32(0) ? admins.length : 0; }
    function getRoleMember(bytes32, uint256 i) external view returns (address) { return admins[i]; }
}
contract VaultLike {
    address public authorizerAddr;
    function setAuthorizer(address a) external { authorizerAddr = a; }
    function getAuthorizer() external view returns (address) { return authorizerAddr; }
}
contract FactoryUpgradeAdminLike {
    address public upgradeAdmin;
    function setUpgradeAdmin(address a) external { upgradeAdmin = a; }
}
contract CurveAdminLike {
    address public dao;
    address public emergency;
    function set(address d, address e) external { dao = d; emergency = e; }
}
contract DSPauseLike {
    function delay() external pure returns (uint256) { return 172800; }
    function authority() external pure returns (address) { return address(uint160(uint256(keccak256("chief")))); }
    function plans(bytes32) external pure returns (bool) { return false; }
}
contract PauseProxyLike {
    address public owner;
    function setOwner(address o) external { owner = o; }
}
contract WardsLike {
    mapping(address => uint256) public wards;
    function rely(address a) external { wards[a] = 1; }
}
// A 2-of-3 Safe as the probe sees it: getThreshold() and getOwners().
contract MultisigLike {
    function getThreshold() external pure returns (uint256) { return 2; }
    function getOwners() external pure returns (address[] memory o) {
        o = new address[](3);
        o[0] = address(0x1001); o[1] = address(0x1002); o[2] = address(0x1003);
    }
}

// OpenZeppelin AccessManager surface: role ids, execution delays, role admins, function roles.
contract AccessManagerLike {
    event RoleGranted(uint64 indexed roleId, address indexed account, uint32 delay, uint48 since, bool newMember);
    event RoleRevoked(uint64 indexed roleId, address indexed account);
    event TargetFunctionRoleUpdated(address indexed target, bytes4 selector, uint64 indexed roleId);
    mapping(address => bool) public isTargetClosed;
    mapping(address => uint32) public getTargetAdminDelay;
    mapping(uint64 => uint32) public getRoleGrantDelay;
    mapping(uint64 => mapping(address => uint48)) internal pendingSince;
    mapping(uint64 => mapping(address => uint32)) internal delayOf;
    mapping(uint64 => mapping(address => bool)) internal member;
    mapping(uint64 => uint64) public getRoleAdmin;
    mapping(address => mapping(bytes4 => uint64)) internal fnRole;
    function ADMIN_ROLE() external pure returns (uint64) { return 0; }
    function PUBLIC_ROLE() external pure returns (uint64) { return type(uint64).max; }
    function hasRole(uint64 r, address a) external view returns (bool, uint32) { return (member[r][a], delayOf[r][a]); }
    function getRoleGuardian(uint64) external pure returns (uint64) { return 0; }
    function getTargetFunctionRole(address t, bytes4 s) external view returns (uint64) { return fnRole[t][s]; }
    function grant(uint64 r, address a, uint32 d) external {
        member[r][a] = true; delayOf[r][a] = d;
        emit RoleGranted(r, a, d, uint48(block.timestamp), true);
    }
    function revoke(uint64 r, address a) external { member[r][a] = false; emit RoleRevoked(r, a); }
    function setAdmin(uint64 r, uint64 admin) external { getRoleAdmin[r] = admin; }
    function setFn(address t, bytes4 s, uint64 r) external { fnRole[t][s] = r; emit TargetFunctionRoleUpdated(t, s, r); }
    function close(address t) external { isTargetClosed[t] = true; }
    function setTargetDelay(address t, uint32 d) external { getTargetAdminDelay[t] = d; }
    function setGrantDelay(uint64 r, uint32 d) external { getRoleGrantDelay[r] = d; }
    function grantLater(uint64 r, address a, uint48 since) external {
        pendingSince[r][a] = since;
        emit RoleGranted(r, a, 0, since, true);
    }
    function getAccess(uint64 r, address a) external view returns (uint48, uint32, uint32, uint48) {
        return (pendingSince[r][a], delayOf[r][a], 0, 0);
    }
}

contract ManagedLike {
    address public authority;
    function setAuthority(address a) external { authority = a; }
    function pause() external {}
}

contract CloneMaker {
    address public last;
    function clone(address impl) external returns (address c) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, impl))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            c := create(0, ptr, 0x37)
        }
        last = c;
    }
}

contract FundsLike {
    address public owner;
    address public fundsHolder;
    address public curator;
    constructor() { owner = msg.sender; }
    function set(address f, address c) external { fundsHolder = f; curator = c; }
}

contract DelayParamLike {
    address public owner;
    uint256 public delay = 60;      // a price-update parameter, not a timelock
    constructor() { owner = msg.sender; }
}

/// Getters with an address-looking name that do not return an address.
contract JunkGetters {
    function emergency() external pure returns (bool) { return true; }
    function guardian() external pure returns (uint256) { return 86400; }
    function curator() external pure returns (string memory) { return "x"; }
    function owner() external pure returns (bytes32) { return keccak256("not an address"); }
}

/// Answers every call with the same 96 bytes, as some proxies and diamonds do.
contract CatchAll {
    fallback() external {
        assembly {
            mstore(0, 1)
            mstore(32, 0xffffffffffffffff)
            mstore(64, 1)
            return(0, 96)
        }
    }
}

contract SettableOwner {
    address public owner;
    constructor() { owner = msg.sender; }
    function setOwner(address a) external { owner = a; }
}

contract SafeWithModule {
    address[] internal mods;
    function getThreshold() external pure returns (uint256) { return 2; }
    function getOwners() external pure returns (address[] memory o) {
        o = new address[](4);
        o[0] = address(uint160(uint256(keccak256("s0")))); o[1] = address(uint160(uint256(keccak256("s1"))));
        o[2] = address(uint160(uint256(keccak256("s2")))); o[3] = address(uint160(uint256(keccak256("s3"))));
    }
    function addModule(address m) external { mods.push(m); }
    function getModulesPaginated(address, uint256) external view returns (address[] memory, address) { return (mods, address(1)); }
}

contract ProposerTimelock {
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    mapping(bytes32 => mapping(address => bool)) internal r;
    function getMinDelay() external pure returns (uint256) { return 172800; }
    function give(bytes32 role, address a) external { r[role][a] = true; }
    function hasRole(bytes32 role, address a) external view returns (bool) { return r[role][a]; }
}

contract VaultWithSafe {
    address public safe;
    function totalAssets() external pure returns (uint256) { return 1; }
    function set(address a) external { safe = a; }
}

contract ModuleWithSafe {
    address public safe;
    function set(address a) external { safe = a; }
}

// A UUPS-style proxy whose upgrade gate answers to getAdmin() and has no admin() or owner().
contract GetAdminLike {
    address public immutable holder;

    constructor(address holder_) {
        holder = holder_;
    }

    function getAdmin() external view returns (address) {
        return holder;
    }
}

/// An UpgradeableBeacon as proxies read it: implementation() and owner().
contract BeaconLike {
    address public implementation;
    address public owner = msg.sender;
    function upgradeTo(address impl) external { implementation = impl; }
}

/// Compound-style Timelock: admin() and delay(), transactions queued by hash.
contract CompoundTimelockLike {
    address public admin = msg.sender;
    uint256 public delay = 172800;
    mapping(bytes32 => bool) public queuedTransactions;
    function setDelay(uint256 d) external { delay = d; }
    function queueTransaction(address target, uint256 value, string calldata signature, bytes calldata data, uint256 eta)
        external returns (bytes32 h)
    {
        h = keccak256(abi.encode(target, value, signature, data, eta));
        queuedTransactions[h] = true;
    }
}

/// Zodiac Delay modifier surface: its modules queue transactions that anyone executes after txCooldown.
contract DelayModuleLike {
    address[] internal mods;
    uint256 public txCooldown = 7 days;
    uint256 public queueNonce;
    function addModule(address m) external { mods.push(m); }
    function getModulesPaginated(address, uint256) external view returns (address[] memory, address) { return (mods, address(1)); }
}

/// Real OpenZeppelin-style AccessControl: grantRole checks the role's admin, so the DEFAULT_ADMIN_ROLE holder can grant
/// and a stranger cannot. `probe --prove` simulates grantRole(DEFAULT_ADMIN_ROLE, dummy): it succeeds from the holder
/// and reverts from a stranger, so the finding is proven.
contract AccessControlLike {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    mapping(bytes32 => mapping(address => bool)) internal _has;
    mapping(bytes32 => bytes32) internal _admin;        // role -> admin role, default DEFAULT_ADMIN_ROLE
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    constructor() { _has[DEFAULT_ADMIN_ROLE][msg.sender] = true; }
    function hasRole(bytes32 role, address a) public view returns (bool) { return _has[role][a]; }
    function getRoleAdmin(bytes32 role) public view returns (bytes32) { return _admin[role]; }
    function grantRole(bytes32 role, address a) external {
        require(_has[getRoleAdmin(role)][msg.sender], "AccessControl: missing role");
        _has[role][a] = true;
        emit RoleGranted(role, a, msg.sender);
    }
}

/// onlyOwner transferOwnership that proves: it succeeds from the owner and reverts from anyone else.
contract RealOwnable {
    address public owner = msg.sender;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    function transferOwnership(address n) external {
        require(msg.sender == owner, "Ownable: caller is not the owner");
        require(n != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(owner, n);
        owner = n;
    }
}

/// An owner whose transferOwnership is also gated by a flag that defaults to false, so the call reverts for the owner
/// and for a stranger alike. `probe --prove` must report this "not simulated" (gated by state, not the caller), never
/// proven: a revert from both says nothing about who holds the key.
contract LockedOwnable {
    address public owner = msg.sender;
    bool public unlocked;        // false until set: the gate is shut
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    function setUnlocked(bool v) external { require(msg.sender == owner, "owner"); unlocked = v; }
    function transferOwnership(address n) external {
        require(unlocked, "locked");
        require(msg.sender == owner, "Ownable: caller is not the owner");
        emit OwnershipTransferred(owner, n);
        owner = n;
    }
}

/// OpenZeppelin TimelockController surface enough to prove a proposer: getMinDelay(), PROPOSER_ROLE and a schedule()
/// gated on it and the delay. `probe --prove` schedules a dummy operation at the minimum delay: it succeeds from a
/// proposer and reverts from a stranger. Nothing is committed (eth_call only).
contract ScheduleTimelockLike {
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    mapping(bytes32 => mapping(address => bool)) internal _roles;
    mapping(bytes32 => uint256) public getTimestamp;
    constructor() { _roles[bytes32(0)][msg.sender] = true; }
    function getMinDelay() external pure returns (uint256) { return 172800; }
    function give(bytes32 r, address a) external { _roles[r][a] = true; }
    function hasRole(bytes32 r, address a) public view returns (bool) { return _roles[r][a]; }
    function schedule(address target, uint256 value, bytes calldata data, bytes32 pred, bytes32 salt, uint256 delay) external {
        require(hasRole(PROPOSER_ROLE, msg.sender), "proposer");
        require(delay >= 172800, "delay");
        bytes32 id = keccak256(abi.encode(target, value, data, pred, salt));
        require(getTimestamp[id] == 0, "exists");
        getTimestamp[id] = block.timestamp + delay;
    }
}
