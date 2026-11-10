// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ReviewPurchases, IERC20} from "../src/ReviewPurchases.sol";

/// Deploy the one-time control-review purchase contract (ReviewPurchases).
///   forge script script/DeployReview.s.sol --rpc-url https://mainnet.base.org --broadcast --private-key $(grep -o '0x[0-9a-f]\{64\}' ~/.config/ownerwatch/wallet.txt)
/// Env: TOKEN (default Base USDC), PRICE (default 400e6 = 400 USDC flat, matching docs/one-time-review.md).
/// After deploy: fill the address into docs/one-time-review.md and watch for ReviewPurchased events.
contract DeployReview is Script {
    address constant BASE_USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    function run() external {
        address token = vm.envOr("TOKEN", BASE_USDC);
        uint256 price = vm.envOr("PRICE", uint256(400e6));
        vm.startBroadcast();
        ReviewPurchases rp = new ReviewPurchases(IERC20(token), price);
        vm.stopBroadcast();
        console.log("ReviewPurchases deployed at", address(rp));
        console.log("token", token, "price", price);
    }
}
