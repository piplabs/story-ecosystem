// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { Upgrades, Options } from "@openzeppelin/foundry-upgrades/Upgrades.sol";

/// @title Upgrade
/// @notice Upgrade script for IPDerivativeAgent contract
/// @dev To use, run the following command:
/// forge script script/Upgrade.s.sol:Upgrade --sig "run()" --account <account-name>
/// --rpc-url $RPC_URL --broadcast --verify  --verifier=blockscout --verifier-url $VERIFIER_URL
contract Upgrade is Script {
    function run() public {
        address agent = vm.envAddress("AGENT");
        address licensingModule = vm.envAddress("LICENSING_MODULE");
        address royaltyModule = vm.envAddress("ROYALTY_MODULE");
        Options memory options;
        options.constructorData = abi.encode(licensingModule, royaltyModule);

        vm.startBroadcast();

        console2.log("Upgrading IPDerivativeAgent...");
        Upgrades.upgradeProxy(agent, "IPDerivativeAgent.sol", "", options);
        console2.log("IPDerivativeAgent upgraded");

        vm.stopBroadcast();
    }
}
