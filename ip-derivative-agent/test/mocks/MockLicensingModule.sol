// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { MockRoyaltyModule } from "./MockRoyaltyModule.sol";

contract MockLicensingModule {
    address public currencyToken;
    MockRoyaltyModule public royaltyModule;
    uint256 public predictedFee;
    uint256 public actualFee;
    bool public registerDerivativeCalled;

    constructor(address _royaltyModule) {
        royaltyModule = MockRoyaltyModule(_royaltyModule);
    }

    function setMintingFee(address _currencyToken, uint256 _predictedFee, uint256 _actualFee) external {
        currencyToken = _currencyToken;
        predictedFee = _predictedFee;
        actualFee = _actualFee;
    }

    function predictMintingLicenseFee(
        address,
        address,
        uint256,
        uint256,
        address,
        bytes calldata
    ) external view returns (address, uint256) {
        return (address(currencyToken), predictedFee);
    }

    function registerDerivative(
        address childIpId,
        address[] calldata,
        uint256[] calldata,
        address,
        bytes calldata,
        uint256,
        uint32,
        uint32
    ) external {
        registerDerivativeCalled = true;
        if (actualFee > 0) {
            royaltyModule.payLicenseMintingFee(childIpId, msg.sender, address(currencyToken), actualFee);
        }
    }
}
