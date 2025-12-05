// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { IPDerivativeAgent } from "../src/IPDerivativeAgent.sol";

/// @title Deploy
/// @notice Deployment script for IPDerivativeAgent contract
/// @dev To use, run the following command:
/// forge script script/Deploy.s.sol:Deploy --sig "run()" --account <account-name> --sender $DEPLOYER
/// --rpc-url $RPC_URL --broadcast --verify  --verifier=blockscout --verifier-url $VERIFIER_URL
contract Deploy is Script {
    function run() public {
        address owner = vm.envAddress("OWNER");
        address licensingModule = vm.envAddress("LICENSING_MODULE");
        address royaltyModule = vm.envAddress("ROYALTY_MODULE");

        vm.startBroadcast();

        console2.log("Deploying IPDerivativeAgent...");
        IPDerivativeAgent agent = new IPDerivativeAgent(owner, licensingModule, royaltyModule);
        console2.log("IPDerivativeAgent deployed to:", address(agent));

        vm.stopBroadcast();
    }
}
