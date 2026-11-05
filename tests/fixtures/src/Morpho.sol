// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Morpho Blue, MetaMorpho V1, Morpho Vault V2 and collateral tokens, cut down to the getters
/// `ownerwatch collateral` reads, with setters so a test can lay out any vault.

struct MarketParams { address loanToken; address collateralToken; address oracle; address irm; uint256 lltv; }

contract MorphoBlueLike {
    struct Position { uint256 supplyShares; uint128 borrowShares; uint128 collateral; }
    struct Market { uint128 totalSupplyAssets; uint128 totalSupplyShares; uint128 totalBorrowAssets; uint128 totalBorrowShares; uint128 lastUpdate; uint128 fee; }
    mapping(bytes32 => MarketParams) public idToMarketParams;
    mapping(bytes32 => mapping(address => Position)) public position;
    mapping(bytes32 => Market) public market;

    function createMarket(address loan, address collateral, address oracle, uint256 lltv) external returns (bytes32 id) {
        MarketParams memory p = MarketParams(loan, collateral, oracle, address(0x1001), lltv);
        id = keccak256(abi.encode(p));
        idToMarketParams[id] = p;
    }
    function setTotals(bytes32 id, uint128 assets, uint128 shares) external {
        market[id].totalSupplyAssets = assets;
        market[id].totalSupplyShares = shares;
    }
    function setShares(bytes32 id, address who, uint256 shares) external { position[id][who].supplyShares = shares; }
}

contract LoanToken {
    string public symbol = "USDT";
    string public name = "Loan Dollar";
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;
    function setBalance(address a, uint256 v) external { balanceOf[a] = v; }
}

contract MetaMorphoLike {
    struct MarketConfig { uint184 cap; bool enabled; uint64 removableAt; }
    address public MORPHO;
    address public asset;
    address public owner = msg.sender;
    address public curator = msg.sender;
    address public guardian;
    uint256 public timelock = 3 days;
    uint256 public totalAssets;
    uint256 public lostAssets;
    uint256 public totalSupply;
    string public name = "Test USDT Vault";
    string public symbol = "tvUSDT";
    uint8 public decimals = 18;
    bytes32[] public withdrawQueue;
    bytes32[] public supplyQueue;
    mapping(bytes32 => MarketConfig) public config;
    mapping(address => uint256) public balanceOf;

    function init(address morpho, address asset_) external { MORPHO = morpho; asset = asset_; }
    function withdrawQueueLength() external view returns (uint256) { return withdrawQueue.length; }
    function supplyQueueLength() external view returns (uint256) { return supplyQueue.length; }
    function add(bytes32 id, uint184 cap, bool supply) external {
        withdrawQueue.push(id);
        if (supply) supplyQueue.push(id);
        config[id] = MarketConfig(cap, true, 0);
    }
    function setTotalAssets(uint256 a) external { totalAssets = a; }
    function setShares(address who, uint256 s, uint256 total) external { balanceOf[who] = s; totalSupply = total; }
}

contract VaultV2Like {
    address public asset;
    address public owner = msg.sender;
    address public curator = msg.sender;
    uint256 public totalAssets;
    string public name = "Test V2 Vault";
    string public symbol = "tv2USDT";
    uint8 public decimals = 18;
    address[] public adapters;

    function init(address asset_) external { asset = asset_; }
    function adaptersLength() external view returns (uint256) { return adapters.length; }
    function addAdapter(address a) external { adapters.push(a); }
    function setTotalAssets(uint256 a) external { totalAssets = a; }
}

contract MarketAdapterLike {
    address public morpho;
    bytes32[] public marketIds;
    function init(address m) external { morpho = m; }
    function marketIdsLength() external view returns (uint256) { return marketIds.length; }
    function add(bytes32 id) external { marketIds.push(id); }
}

contract VaultAdapterLike {
    address public morphoVaultV1;
    function init(address v) external { morphoVaultV1 = v; }
}

contract OtherAdapterLike {
    uint256 public realAssets = 7_000000;
}

/// Ownable token: the owner mints (no return value) and pauses.
contract OwnedMintToken {
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    string public symbol = "OMT";
    string public name = "Owned Mint Token";
    uint8 public decimals = 18;
    address public owner = msg.sender;
    bool public paused;
    mapping(address => uint256) public balanceOf;
    function transferOwnership(address n) external { require(msg.sender == owner, "owner"); emit OwnershipTransferred(owner, n); owner = n; }
    function mint(address to, uint256 a) external { require(msg.sender == owner, "owner"); balanceOf[to] += a; }
    function pause() external { require(msg.sender == owner, "owner"); paused = true; }
}

/// AccessControlEnumerable surface: members are listed, so no candidate list is needed.
contract RoleMintToken {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    string public symbol = "RMT";
    string public name = "Role Mint Token";
    uint8 public decimals = 18;
    mapping(bytes32 => address[]) internal members;
    constructor() { members[bytes32(0)].push(msg.sender); }
    function grant(bytes32 r, address a) external { members[r].push(a); }
    function hasRole(bytes32 r, address a) public view returns (bool) {
        for (uint256 i; i < members[r].length; i++) if (members[r][i] == a) return true;
        return false;
    }
    function getRoleMemberCount(bytes32 r) external view returns (uint256) { return members[r].length; }
    function getRoleMember(bytes32 r, uint256 i) external view returns (address) { return members[r][i]; }
    function mint(address, uint256) external view { require(hasRole(MINTER_ROLE, msg.sender), "role"); }
}

/// AccessControl without enumeration, with its admin and minter outside anything the report can see.
contract HiddenRoleToken {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    string public symbol = "HRT";
    string public name = "Hidden Role Token";
    uint8 public decimals = 18;
    mapping(bytes32 => mapping(address => bool)) internal r;
    function give(bytes32 role, address a) external { r[role][a] = true; }
    function hasRole(bytes32 role, address a) public view returns (bool) { return r[role][a]; }
    function mint(address, uint256) external view { require(hasRole(MINTER_ROLE, msg.sender), "role"); }
}

contract PlainToken {
    string public symbol = "PLN";
    string public name = "Plain Token";
    uint8 public decimals = 18;
}

/// ERC-4626 surface: shares minted against deposits of asset().
contract Wrapper4626 {
    string public symbol = "wOMT";
    string public name = "Wrapped OMT";
    uint8 public decimals = 18;
    address public asset;
    uint256 public totalAssets;
    function init(address a) external { asset = a; }
}

/// ERC-1967 proxy with no admin slot: the implementation decides who upgrades (UUPS).
contract UupsProxy {
    bytes32 internal constant IMPL = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    function setUp(address impl, address owner_, address upgrader_) external {
        assembly { sstore(IMPL, impl) sstore(0, owner_) sstore(1, upgrader_) }
    }
    fallback() external payable {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), sload(IMPL), 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
}

/// UUPS implementation: owner() is public, the upgrader is not, and only the upgrader can upgrade.
contract UupsToken {
    address public owner;
    address internal upgrader;
    function symbol() external pure returns (string memory) { return "UUP"; }
    function decimals() external pure returns (uint8) { return 18; }
    function upgradeToAndCall(address, bytes calldata) external payable { require(msg.sender == upgrader, "upgrader"); }
}

contract OracleOwned {
    address public owner = msg.sender;
    function price() external pure returns (uint256) { return 1e36; }
}

contract FeedLike {
    address public owner = msg.sender;
    string public description = "OMT / USD";
}

/// MorphoChainlinkOracleV2 surface: immutable, with feeds that have owners.
contract OracleWithFeed {
    address public BASE_FEED_1;
    function init(address f) external { BASE_FEED_1 = f; }
    function price() external pure returns (uint256) { return 1e36; }
}
