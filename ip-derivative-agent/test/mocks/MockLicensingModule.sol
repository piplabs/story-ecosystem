// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

contract MockLicensingModule {
    address public currencyToken;
    uint256 public tokenAmount;
    bool public registerDerivativeCalled;

    function setMintingFee(address _currencyToken, uint256 _tokenAmount) external {
        currencyToken = _currencyToken;
        tokenAmount = _tokenAmount;
    }

    function predictMintingLicenseFee(
        address,
        address,
        uint256,
        uint256,
        address,
        bytes calldata
    ) external view returns (address, uint256) {
        return (currencyToken, tokenAmount);
    }

    function registerDerivative(
        address,
        address[] calldata,
        uint256[] calldata,
        address,
        bytes calldata,
        uint256,
        uint32,
        uint32
    ) external {
        registerDerivativeCalled = true;
    }
}
