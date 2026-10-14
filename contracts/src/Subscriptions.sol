// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title ownerwatch hosted-tier subscriptions
/// @notice Pay USDC (or any ERC-20) for N months of hosted monitoring. No accounts,
///         no invoices: `subscribe` pulls tokens and extends `expiry[msg.sender]`.
///         The off-chain service treats an address as a customer while
///         `isActive(addr)` is true and reads the config it points to via `configRef`.
contract Subscriptions {
    event Subscribed(address indexed account, uint256 months, uint256 paid, uint256 newExpiry, bytes32 configRef);
    event ConfigUpdated(address indexed account, bytes32 configRef);
    event PriceUpdated(uint256 pricePerMonth);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Withdrawn(address indexed to, uint256 amount);

    error NotOwner();
    error ZeroMonths();
    error TooManyMonths();
    error TransferFailed();
    error NotActive();

    uint256 public constant MONTH = 30 days;
    uint256 public constant MAX_MONTHS = 24;

    IERC20 public immutable token;      // e.g. USDC
    address public owner;
    uint256 public pricePerMonth;       // in token units (USDC: 6 decimals)

    mapping(address => uint256) public expiry;
    mapping(address => bytes32) public configRef;   // IPFS CID hash or keccak of the YAML the customer sent

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(IERC20 token_, uint256 pricePerMonth_) {
        token = token_;
        owner = msg.sender;
        pricePerMonth = pricePerMonth_;
        emit OwnershipTransferred(address(0), msg.sender);
        emit PriceUpdated(pricePerMonth_);
    }

    /// @notice Buy `months` months. Extends from current expiry if still active, else from now.
    function subscribe(uint256 months, bytes32 ref) external {
        if (months == 0) revert ZeroMonths();
        if (months > MAX_MONTHS) revert TooManyMonths();
        uint256 cost = months * pricePerMonth;
        if (!token.transferFrom(msg.sender, address(this), cost)) revert TransferFailed();
        uint256 base = expiry[msg.sender] > block.timestamp ? expiry[msg.sender] : block.timestamp;
        uint256 newExpiry = base + months * MONTH;
        expiry[msg.sender] = newExpiry;
        if (ref != bytes32(0)) configRef[msg.sender] = ref;
        emit Subscribed(msg.sender, months, cost, newExpiry, ref);
    }

    /// @notice Point an active subscription at a new config.
    function setConfig(bytes32 ref) external {
        if (!isActive(msg.sender)) revert NotActive();
        configRef[msg.sender] = ref;
        emit ConfigUpdated(msg.sender, ref);
    }

    function isActive(address account) public view returns (bool) {
        return expiry[account] > block.timestamp;
    }

    // ---- owner ----
    function setPrice(uint256 pricePerMonth_) external onlyOwner {
        pricePerMonth = pricePerMonth_;
        emit PriceUpdated(pricePerMonth_);
    }

    function withdraw(address to, uint256 amount) external onlyOwner {
        if (!token.transfer(to, amount)) revert TransferFailed();
        emit Withdrawn(to, amount);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
