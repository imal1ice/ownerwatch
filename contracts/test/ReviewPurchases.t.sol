// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ReviewPurchases, IERC20} from "../src/ReviewPurchases.sol";

contract MockUSDC is IERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 a) external { balanceOf[to] += a; }
    function approve(address s, uint256 a) external { allowance[msg.sender][s] = a; }
    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a; balanceOf[to] += a; return true;
    }
    function transferFrom(address f, address t, uint256 a) external returns (bool) {
        allowance[f][msg.sender] -= a; balanceOf[f] -= a; balanceOf[t] += a; return true;
    }
}

/// USDT-style: no return values.
contract MockUSDT {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 a) external { balanceOf[to] += a; }
    function approve(address s, uint256 a) external { allowance[msg.sender][s] = a; }
    function transfer(address to, uint256 a) external { balanceOf[msg.sender] -= a; balanceOf[to] += a; }
    function transferFrom(address f, address t, uint256 a) external { allowance[f][msg.sender] -= a; balanceOf[f] -= a; balanceOf[t] += a; }
}

/// Fee-on-transfer: recipient gets 99%.
contract MockFeeToken is IERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 a) external { balanceOf[to] += a; }
    function approve(address s, uint256 a) external { allowance[msg.sender][s] = a; }
    function transfer(address to, uint256 a) external returns (bool) { balanceOf[msg.sender] -= a; balanceOf[to] += a * 99 / 100; return true; }
    function transferFrom(address f, address t, uint256 a) external returns (bool) {
        allowance[f][msg.sender] -= a; balanceOf[f] -= a; balanceOf[t] += a * 99 / 100; return true;
    }
}

contract ReviewPurchasesTest is Test {
    MockUSDC usdc;
    ReviewPurchases rp;
    address buyer = address(0xB0B);
    address target = address(0x7A6);
    uint256 constant PRICE = 400e6; // 400 USDC flat

    event ReviewPurchased(address indexed buyer, address indexed target, uint256 indexed chainId, uint256 paid, bytes32 ref);

    function setUp() public {
        usdc = new MockUSDC();
        rp = new ReviewPurchases(usdc, PRICE);
        usdc.mint(buyer, 10_000e6);
        vm.prank(buyer);
        usdc.approve(address(rp), type(uint256).max);
    }

    function test_buy_pulls_fee_and_emits_order() public {
        vm.expectEmit(true, true, true, true);
        emit ReviewPurchased(buyer, target, 1, PRICE, bytes32("mail-hash"));
        vm.prank(buyer);
        rp.buy(target, 1, PRICE, bytes32("mail-hash"));
        assertEq(usdc.balanceOf(address(rp)), PRICE);
        assertEq(usdc.balanceOf(buyer), 10_000e6 - PRICE);
    }

    function test_buy_reverts_on_zero_target() public {
        vm.prank(buyer);
        vm.expectRevert(ReviewPurchases.ZeroTarget.selector);
        rp.buy(address(0), 1, PRICE, bytes32(0));
    }

    function test_buy_reverts_when_price_above_maxCost() public {
        vm.prank(buyer);
        vm.expectRevert(abi.encodeWithSelector(ReviewPurchases.CostAboveMax.selector, PRICE, PRICE - 1));
        rp.buy(target, 1, PRICE - 1, bytes32(0));
    }

    function test_price_change_then_maxCost_guard() public {
        rp.setPrice(500e6);
        vm.prank(buyer);
        vm.expectRevert(abi.encodeWithSelector(ReviewPurchases.CostAboveMax.selector, 500e6, PRICE));
        rp.buy(target, 1, PRICE, bytes32(0)); // buyer only authorised 400, price is now 500 -> revert
    }

    function test_usdt_style_token_no_bool() public {
        MockUSDT usdt = new MockUSDT();
        ReviewPurchases rp2 = new ReviewPurchases(IERC20(address(usdt)), PRICE);
        usdt.mint(buyer, 10_000e6);
        vm.startPrank(buyer);
        usdt.approve(address(rp2), type(uint256).max);
        rp2.buy(target, 10, PRICE, bytes32(0));
        vm.stopPrank();
        assertEq(usdt.balanceOf(address(rp2)), PRICE);
    }

    function test_fee_on_transfer_token_reverts_short() public {
        MockFeeToken fee = new MockFeeToken();
        ReviewPurchases rp3 = new ReviewPurchases(fee, PRICE);
        fee.mint(buyer, 10_000e6);
        vm.startPrank(buyer);
        fee.approve(address(rp3), type(uint256).max);
        vm.expectRevert(abi.encodeWithSelector(ReviewPurchases.ShortReceived.selector, PRICE, PRICE * 99 / 100));
        rp3.buy(target, 1, PRICE, bytes32(0));
        vm.stopPrank();
    }

    function test_setPrice_only_owner() public {
        vm.prank(buyer);
        vm.expectRevert(ReviewPurchases.NotOwner.selector);
        rp.setPrice(1);
        rp.setPrice(1e6);
        assertEq(rp.price(), 1e6);
    }

    function test_withdraw_only_owner_and_moves_funds() public {
        vm.prank(buyer);
        rp.buy(target, 1, PRICE, bytes32(0));
        vm.prank(buyer);
        vm.expectRevert(ReviewPurchases.NotOwner.selector);
        rp.withdraw(buyer, PRICE);
        rp.withdraw(address(0xBEEF), PRICE);
        assertEq(usdc.balanceOf(address(0xBEEF)), PRICE);
        assertEq(usdc.balanceOf(address(rp)), 0);
    }

    function test_withdraw_zero_address_reverts() public {
        vm.expectRevert(ReviewPurchases.ZeroAddress.selector);
        rp.withdraw(address(0), 0);
    }

    function test_two_step_ownership() public {
        address newOwner = address(0xCAFE);
        rp.transferOwnership(newOwner);
        assertEq(rp.pendingOwner(), newOwner);
        assertEq(rp.owner(), address(this)); // not yet
        vm.prank(address(0xDEAD));
        vm.expectRevert(ReviewPurchases.NotPendingOwner.selector);
        rp.acceptOwnership();
        vm.prank(newOwner);
        rp.acceptOwnership();
        assertEq(rp.owner(), newOwner);
        assertEq(rp.pendingOwner(), address(0));
    }
}
