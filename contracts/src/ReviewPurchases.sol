// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title ownerwatch one-time control-review purchases
/// @notice Pay a flat stablecoin fee once to order a written control-surface review of an EVM
///         deployment. No account, no invoice and no reply needed: `buy` pulls the fee and emits
///         `ReviewPurchased` with the target address and chain id for the operator to see and fulfil.
///         Delivery is manual and off-chain; a buyer should read the terms (including where the
///         operator is based) before paying. See docs/one-time-review.md.
/// @dev    Mirrors the transfer handling of Subscriptions.sol. Intended for USDC; tokens that return
///         no bool (USDT-style) are handled; fee-on-transfer tokens are rejected because the full fee
///         must arrive. Funds are held until the owner withdraws. No on-chain refund.
contract ReviewPurchases {
    event ReviewPurchased(address indexed buyer, address indexed target, uint256 indexed chainId, uint256 paid, bytes32 ref);
    event PriceUpdated(uint256 price);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Withdrawn(address indexed to, uint256 amount);

    error NotOwner();
    error NotPendingOwner();
    error ZeroAddress();
    error ZeroTarget();
    error CostAboveMax(uint256 cost, uint256 maxCost);
    error TransferFailed();
    error ShortReceived(uint256 expected, uint256 received);

    IERC20 public immutable token;      // e.g. USDC
    address public owner;
    address public pendingOwner;
    uint256 public price;               // flat fee in token units (USDC: 6 decimals)

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(IERC20 token_, uint256 price_) {
        if (address(token_) == address(0)) revert ZeroAddress();
        token = token_;
        owner = msg.sender;
        price = price_;
        emit OwnershipTransferred(address(0), msg.sender);
        emit PriceUpdated(price_);
    }

    /// @notice Order one review of `target` on chain `chainId`. Pulls `price` tokens from the caller.
    ///         `maxCost` guards against a price change between the tx being submitted and included.
    ///         `ref` is an optional label the buyer chooses (e.g. a contact hash); it is not read on-chain.
    function buy(address target, uint256 chainId, uint256 maxCost, bytes32 ref) external {
        if (target == address(0)) revert ZeroTarget();
        uint256 cost = price;
        if (cost > maxCost) revert CostAboveMax(cost, maxCost);

        // effects (no stored state changes; the order is the event)
        emit ReviewPurchased(msg.sender, target, chainId, cost, ref);

        // interaction: require the full fee to arrive (rejects fee-on-transfer tokens)
        uint256 before = token.balanceOf(address(this));
        _safeTransferFrom(msg.sender, address(this), cost);
        uint256 received = token.balanceOf(address(this)) - before;
        if (received < cost) revert ShortReceived(cost, received);
    }

    // ---- owner ----
    function setPrice(uint256 price_) external onlyOwner {
        price = price_;
        emit PriceUpdated(price_);
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
