// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title ownerwatch hosted-tier subscriptions
/// @notice Pay a stablecoin for N 30-day periods of hosted monitoring on `chains` chains.
///         No accounts, no invoices: `subscribe` pulls tokens and extends `expiry[msg.sender]`.
///         The off-chain runner treats an address as a customer while `isActive(addr)` is
///         true, runs at most `chainCount[addr]` chains, and reads the config it labels via `configRef`.
/// @dev    Intended for USDC. Tokens that return no bool (USDT-style) are handled; fee-on-transfer
///         tokens are rejected because the contract requires the full amount to arrive.
contract Subscriptions {
    event Subscribed(address indexed account, uint256 periods, uint256 chains, uint256 paid, uint256 newExpiry, bytes32 configRef);
    event ConfigUpdated(address indexed account, bytes32 configRef);
    event PriceUpdated(uint256 pricePerPeriod);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Withdrawn(address indexed to, uint256 amount);

    error NotOwner();
    error NotPendingOwner();
    error ZeroAddress();
    error ZeroPeriods();
    error ZeroChains();
    error TooManyPeriods();
    error TooManyChains();
    error CostAboveMax(uint256 cost, uint256 maxCost);
    error TransferFailed();
    error ShortReceived(uint256 expected, uint256 received);
    error NotActive();

    uint256 public constant PERIOD = 30 days;
    uint256 public constant MAX_PERIODS = 24;
    uint256 public constant MAX_CHAINS = 20;

    IERC20 public immutable token;      // e.g. USDC
    address public owner;
    address public pendingOwner;
    uint256 public pricePerPeriod;      // per chain per 30-day period, in token units (USDC: 6 decimals)

    mapping(address => uint256) public expiry;
    mapping(address => uint256) public chainCount;
    mapping(address => bytes32) public configRef;   // label the customer chooses for the config they sent

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(IERC20 token_, uint256 pricePerPeriod_) {
        if (address(token_) == address(0)) revert ZeroAddress();
        token = token_;
        owner = msg.sender;
        pricePerPeriod = pricePerPeriod_;
        emit OwnershipTransferred(address(0), msg.sender);
        emit PriceUpdated(pricePerPeriod_);
    }

    /// @notice Buy `periods` 30-day periods for `chains` chains. Extends from the current expiry
    ///         if still active, else from now. Reverts if the price moved so cost exceeds `maxCost`.
    function subscribe(uint256 periods, uint256 chains, uint256 maxCost, bytes32 ref) external {
        if (periods == 0) revert ZeroPeriods();
        if (periods > MAX_PERIODS) revert TooManyPeriods();
        if (chains == 0) revert ZeroChains();
        if (chains > MAX_CHAINS) revert TooManyChains();
        uint256 cost = periods * chains * pricePerPeriod;
        if (cost > maxCost) revert CostAboveMax(cost, maxCost);

        // effects
        uint256 base = expiry[msg.sender] > block.timestamp ? expiry[msg.sender] : block.timestamp;
        uint256 newExpiry = base + periods * PERIOD;
        expiry[msg.sender] = newExpiry;
        chainCount[msg.sender] = chains;
        if (ref != bytes32(0)) configRef[msg.sender] = ref;
        emit Subscribed(msg.sender, periods, chains, cost, newExpiry, configRef[msg.sender]);

        // interaction
        uint256 before = token.balanceOf(address(this));
        _safeTransferFrom(msg.sender, address(this), cost);
        uint256 received = token.balanceOf(address(this)) - before;
        if (received < cost) revert ShortReceived(cost, received);
    }

    /// @notice Point an active subscription at a new config label.
    function setConfig(bytes32 ref) external {
        if (!isActive(msg.sender)) revert NotActive();
        configRef[msg.sender] = ref;
        emit ConfigUpdated(msg.sender, ref);
    }

    function isActive(address account) public view returns (bool) {
        return expiry[account] > block.timestamp;
    }

    // ---- owner ----
    function setPrice(uint256 pricePerPeriod_) external onlyOwner {
        pricePerPeriod = pricePerPeriod_;
        emit PriceUpdated(pricePerPeriod_);
    }

    function withdraw(address to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        _safeTransfer(to, amount);
        emit Withdrawn(to, amount);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    // ---- token helpers: tolerate tokens that return nothing ----
    function _safeTransferFrom(address from, address to, uint256 amount) internal {
        (bool ok, bytes memory data) = address(token).call(abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
    }

    function _safeTransfer(address to, uint256 amount) internal {
        (bool ok, bytes memory data) = address(token).call(abi.encodeWithSelector(IERC20.transfer.selector, to, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
    }
}
