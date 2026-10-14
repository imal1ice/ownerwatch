// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Subscriptions, IERC20} from "../src/Subscriptions.sol";

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

contract SubscriptionsTest is Test {
    MockUSDC usdc;
    Subscriptions subs;
    address alice = address(0xA11CE);
    uint256 constant PRICE = 200e6; // 200 USDC / chain / period

    function setUp() public {
        usdc = new MockUSDC();
        subs = new Subscriptions(usdc, PRICE);
        usdc.mint(alice, 100_000e6);
        vm.prank(alice);
        usdc.approve(address(subs), type(uint256).max);
    }

    function test_subscribe_sets_expiry_chains_and_config() public {
        vm.prank(alice);
        subs.subscribe(3, 2, 1200e6, bytes32("cfg"));
        assertEq(subs.expiry(alice), block.timestamp + 90 days);
        assertEq(subs.chainCount(alice), 2);
        assertEq(subs.configRef(alice), bytes32("cfg"));
        assertTrue(subs.isActive(alice));
        assertEq(usdc.balanceOf(address(subs)), 3 * 2 * PRICE);
    }

    function test_renewal_extends_and_keeps_config_in_event() public {
        vm.startPrank(alice);
        subs.subscribe(1, 1, PRICE, bytes32("cfg"));
        uint256 first = subs.expiry(alice);
        vm.warp(block.timestamp + 10 days);
        vm.expectEmit(true, false, false, true);
        emit Subscriptions.Subscribed(alice, 1, 1, PRICE, first + 30 days, bytes32("cfg"));
        subs.subscribe(1, 1, PRICE, 0);
        assertEq(subs.expiry(alice), first + 30 days);
        assertEq(subs.configRef(alice), bytes32("cfg"));
        vm.stopPrank();
    }

    function test_lapsed_subscription_restarts_from_now() public {
        vm.startPrank(alice);
        subs.subscribe(1, 1, PRICE, 0);
        vm.warp(block.timestamp + 100 days);
        assertFalse(subs.isActive(alice));
        subs.subscribe(1, 1, PRICE, 0);
        assertEq(subs.expiry(alice), block.timestamp + 30 days);
        vm.stopPrank();
    }

    function test_price_change_before_subscribe_reverts_on_maxCost() public {
        subs.setPrice(500e6);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Subscriptions.CostAboveMax.selector, 500e6, PRICE));
        subs.subscribe(1, 1, PRICE, 0);
    }

    function test_setConfig_requires_active() public {
        vm.prank(alice);
        vm.expectRevert(Subscriptions.NotActive.selector);
        subs.setConfig(bytes32("x"));
    }

    function test_bounds() public {
        vm.startPrank(alice);
        vm.expectRevert(Subscriptions.ZeroPeriods.selector);
        subs.subscribe(0, 1, 0, 0);
        vm.expectRevert(Subscriptions.TooManyPeriods.selector);
        subs.subscribe(25, 1, type(uint256).max, 0);
        vm.expectRevert(Subscriptions.ZeroChains.selector);
        subs.subscribe(1, 0, 0, 0);
        vm.expectRevert(Subscriptions.TooManyChains.selector);
        subs.subscribe(1, 21, type(uint256).max, 0);
        vm.stopPrank();
    }

    function test_two_step_ownership_and_zero_checks() public {
        vm.expectRevert(Subscriptions.ZeroAddress.selector);
        subs.transferOwnership(address(0));
        subs.transferOwnership(address(0xB0B));
        assertEq(subs.owner(), address(this));
        vm.prank(alice);
        vm.expectRevert(Subscriptions.NotPendingOwner.selector);
        subs.acceptOwnership();
        vm.prank(address(0xB0B));
        subs.acceptOwnership();
        assertEq(subs.owner(), address(0xB0B));
        assertEq(subs.pendingOwner(), address(0));
        vm.expectRevert(Subscriptions.NotOwner.selector);
        subs.setPrice(1);
        vm.expectRevert(Subscriptions.ZeroAddress.selector);
        new Subscriptions(IERC20(address(0)), 1);
    }

    function test_owner_withdraw_and_price() public {
        vm.prank(alice);
        subs.subscribe(2, 1, 2 * PRICE, 0);
        subs.setPrice(150e6);
        assertEq(subs.pricePerPeriod(), 150e6);
        vm.expectRevert(Subscriptions.ZeroAddress.selector);
        subs.withdraw(address(0), 1);
        subs.withdraw(address(0xB0B), 2 * PRICE);
        assertEq(usdc.balanceOf(address(0xB0B)), 2 * PRICE);
        vm.prank(alice);
        vm.expectRevert(Subscriptions.NotOwner.selector);
        subs.withdraw(alice, 1);
    }

    function test_usdt_style_token_works() public {
        MockUSDT usdt = new MockUSDT();
        Subscriptions s2 = new Subscriptions(IERC20(address(usdt)), PRICE);
        usdt.mint(alice, 1000e6);
        vm.startPrank(alice);
        usdt.approve(address(s2), type(uint256).max);
        s2.subscribe(1, 1, PRICE, 0);
        vm.stopPrank();
        assertEq(usdt.balanceOf(address(s2)), PRICE);
        s2.withdraw(address(0xB0B), PRICE);
        assertEq(usdt.balanceOf(address(0xB0B)), PRICE);
    }

    function test_fee_on_transfer_token_rejected() public {
        MockFeeToken fee = new MockFeeToken();
        Subscriptions s2 = new Subscriptions(fee, PRICE);
        fee.mint(alice, 1000e6);
        vm.startPrank(alice);
        fee.approve(address(s2), type(uint256).max);
        vm.expectRevert(abi.encodeWithSelector(Subscriptions.ShortReceived.selector, PRICE, PRICE * 99 / 100));
        s2.subscribe(1, 1, PRICE, 0);
        vm.stopPrank();
    }

    function testFuzz_subscribe(uint8 periods, uint8 chains) public {
        periods = uint8(bound(periods, 1, 24));
        chains = uint8(bound(chains, 1, 20));
        uint256 cost = uint256(periods) * chains * PRICE;
        usdc.mint(alice, cost);
        vm.prank(alice);
        subs.subscribe(periods, chains, cost, 0);
        assertEq(subs.expiry(alice), block.timestamp + uint256(periods) * 30 days);
        assertEq(subs.chainCount(alice), chains);
    }
}
