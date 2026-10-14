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

contract SubscriptionsTest is Test {
    MockUSDC usdc;
    Subscriptions subs;
    address alice = address(0xA11CE);
    uint256 constant PRICE = 200e6; // 200 USDC / month

    function setUp() public {
        usdc = new MockUSDC();
        subs = new Subscriptions(usdc, PRICE);
        usdc.mint(alice, 10_000e6);
        vm.prank(alice);
        usdc.approve(address(subs), type(uint256).max);
    }

    function test_subscribe_sets_expiry_and_config() public {
        vm.prank(alice);
        subs.subscribe(3, bytes32("cfg"));
        assertEq(subs.expiry(alice), block.timestamp + 90 days);
        assertEq(subs.configRef(alice), bytes32("cfg"));
        assertTrue(subs.isActive(alice));
        assertEq(usdc.balanceOf(address(subs)), 3 * PRICE);
    }

    function test_renewal_extends_from_current_expiry() public {
        vm.startPrank(alice);
        subs.subscribe(1, 0);
        uint256 first = subs.expiry(alice);
        vm.warp(block.timestamp + 10 days);
        subs.subscribe(1, 0);
        assertEq(subs.expiry(alice), first + 30 days);
        vm.stopPrank();
    }

    function test_lapsed_subscription_restarts_from_now() public {
        vm.startPrank(alice);
        subs.subscribe(1, 0);
        vm.warp(block.timestamp + 100 days);
        assertFalse(subs.isActive(alice));
        subs.subscribe(1, 0);
        assertEq(subs.expiry(alice), block.timestamp + 30 days);
        vm.stopPrank();
    }

    function test_setConfig_requires_active() public {
        vm.prank(alice);
        vm.expectRevert(Subscriptions.NotActive.selector);
        subs.setConfig(bytes32("x"));
    }

    function test_bounds() public {
        vm.startPrank(alice);
        vm.expectRevert(Subscriptions.ZeroMonths.selector);
        subs.subscribe(0, 0);
        vm.expectRevert(Subscriptions.TooManyMonths.selector);
        subs.subscribe(25, 0);
        vm.stopPrank();
    }

    function test_owner_withdraw_and_price() public {
        vm.prank(alice);
        subs.subscribe(2, 0);
        subs.setPrice(150e6);
        assertEq(subs.pricePerMonth(), 150e6);
        subs.withdraw(address(0xB0B), 2 * PRICE);
        assertEq(usdc.balanceOf(address(0xB0B)), 2 * PRICE);
        vm.prank(alice);
        vm.expectRevert(Subscriptions.NotOwner.selector);
        subs.withdraw(alice, 1);
    }

    function testFuzz_subscribe(uint8 months) public {
        months = uint8(bound(months, 1, 24));
        usdc.mint(alice, uint256(months) * PRICE);
        vm.prank(alice);
        subs.subscribe(months, 0);
        assertEq(subs.expiry(alice), block.timestamp + uint256(months) * 30 days);
    }
}
