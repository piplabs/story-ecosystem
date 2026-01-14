// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MockRoyaltyModule {
    /// @notice Allows to pay the minting fee for a license
    /// @param payerAddress The address that pays the royalties
    /// @param token The token to use to pay the royalties
    /// @param amount The amount to pay
    function payLicenseMintingFee(address, address payerAddress, address token, uint256 amount) external {
        IERC20(token).transferFrom(payerAddress, address(this), amount);
    }
}
