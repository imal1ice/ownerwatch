// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {Subscriptions, IERC20} from "../src/Subscriptions.sol";

/// Deploy the hosted-tier subscription contract.
///   forge script script/Deploy.s.sol --rpc-url https://mainnet.base.org --broadcast --private-key $(grep -o '0x[0-9a-f]\{64\}' ~/.config/ownerwatch/wallet.txt)
/// Env: TOKEN (default Base USDC), PRICE (default 200e6 = 200 USDC per chain per 30-day period).
contract Deploy is Script {
    address constant BASE_USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    function run() external {
        address token = vm.envOr("TOKEN", BASE_USDC);
        uint256 price = vm.envOr("PRICE", uint256(200e6));
        vm.startBroadcast();
        Subscriptions s = new Subscriptions(IERC20(token), price);
        vm.stopBroadcast();
        console.log("Subscriptions deployed at", address(s));
        console.log("token", token, "price/month", price);
    }
}
