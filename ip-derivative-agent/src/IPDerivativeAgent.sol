// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Ownable, Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { ILicensingModule } from "@storyprotocol/core/interfaces/modules/licensing/ILicensingModule.sol";

import { IIPDerivativeAgent } from "./IIPDerivativeAgent.sol";


/// @title IPDerivativeAgent
/// @notice Agent (owner) manages a whitelist of (parentIp, childIp, licenseTemplate, licenseTermsId, licensee).
/// Whitelisted licensees may delegate the agent to register derivatives on behalf of the
/// derivative owner. The minting fee is paid in an ERC-20 token. The agent pulls the token
/// from the licensee, approves the RoyaltyModule to pull it from the agent, and then calls
/// LicensingModule.registerDerivative(...). The agent exposes no regular withdraw function;
/// an emergency withdrawal (ERC20/native) is available only to the owner while paused.
///
/// @dev CRITICAL: Licensees must approve this contract to spend the minting fee token before calling registerDerivativeViaAgent.
/// @dev Wildcard Pattern: Setting licensee = address(0) in whitelist allows ANY caller to register that specific (parent, child, template, license) combo.
contract IPDerivativeAgent is IIPDerivativeAgent, Ownable2Step, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    uint256 public constant MAX_ENTRIES = 1000;

    /// @notice Licensing module to call for derivative registration
    ILicensingModule public immutable LICENSING_MODULE;

    /// @notice Royalty module address (used for token allowance during fee payment)
    address public immutable ROYALTY_MODULE;

    /// @notice Whitelist mapping keyed by keccak256(parentIpId, childIpId, licenseTemplate, licenseTermsId, licensee)
    /// @dev Use address(0) as licensee for wildcard (allows any caller). licenseTermsId must be non-zero.
    mapping(bytes32 => bool) private _whitelist;

    /// @notice Constructor
    /// @param owner Address to transfer ownership to (must be non-zero)
    /// @param _licensingModule LicensingModule address (must be non-zero)
    /// @param _royaltyModule RoyaltyModule address (must be non-zero)
    constructor(address owner, address _licensingModule, address _royaltyModule) Ownable(owner) {
        if (owner == address(0) || _licensingModule == address(0) || _royaltyModule == address(0)) {
            revert IPDerivativeAgent_ZeroAddress();
        }
        LICENSING_MODULE = ILicensingModule(_licensingModule);
        ROYALTY_MODULE = _royaltyModule;
    }

    /// -----------------------------------------------------------------------
    /// Whitelist Management
    /// -----------------------------------------------------------------------

    /// @notice Add a single whitelist entry. Callable by owner only.
    /// @dev Setting licensee = address(0) creates a wildcard entry (any caller can register)
    /// @param entry the entry to whitelist
    function addToWhitelist(
        WhitelistEntry calldata entry
    ) external onlyOwner {
        _addToWhitelist({
            parentIpId: entry.parentIpId,
            childIpId: entry.childIpId,
            licensee: entry.licensee,
            licenseTemplate: entry.licenseTemplate,
            licenseTermsId: entry.licenseTermsId
        });
    }

    /// @notice Remove a single whitelist entry. Callable by owner only.
    /// @param entry the entry to remove from whitelist
    function removeFromWhitelist(
        WhitelistEntry calldata entry
    ) external onlyOwner {
        _removeFromWhitelist({
            parentIpId: entry.parentIpId,
            childIpId: entry.childIpId,
            licensee: entry.licensee,
            licenseTemplate: entry.licenseTemplate,
            licenseTermsId: entry.licenseTermsId
        });
    }

    /// @notice Batch add whitelist entries. 
    /// @param entries Array of WhitelistEntry structs containing whitelist parameters
    function addToWhitelistBatch(WhitelistEntry[] calldata entries) external onlyOwner {
        if (entries.length > MAX_ENTRIES) revert IPDerivativeAgent_TooManyEntries(entries.length, MAX_ENTRIES);
        for (uint256 i = 0; i < entries.length; ) {
            WhitelistEntry calldata entry = entries[i];
            _addToWhitelist({
            parentIpId: entry.parentIpId,
            childIpId: entry.childIpId,
            licensee: entry.licensee,
            licenseTemplate: entry.licenseTemplate,
            licenseTermsId: entry.licenseTermsId
            });
            unchecked { ++i; }
        }
    }

    /// @notice Batch remove whitelist entries. 
    /// @param entries Array of WhitelistEntry structs containing whitelist parameters
    function removeFromWhitelistBatch(WhitelistEntry[] calldata entries) external onlyOwner {
        if (entries.length > MAX_ENTRIES) revert IPDerivativeAgent_TooManyEntries(entries.length, MAX_ENTRIES);
        for (uint256 i = 0; i < entries.length; ) {
            WhitelistEntry calldata entry = entries[i];
            _removeFromWhitelist({
            parentIpId: entry.parentIpId,
            childIpId: entry.childIpId,
            licensee: entry.licensee,
            licenseTemplate: entry.licenseTemplate,
            licenseTermsId: entry.licenseTermsId
            });
            unchecked { ++i; }
        }
    }

    /// @notice Convenience function to add a global whitelist entry (allows any caller)
    /// @notice While a global whitelist entry is set, trying to whitelist a specific caller won't work:
    /// any caller will still be allowed 
    /// @param parentIpId Parent IP address
    /// @param childIpId Child/derivative IP address
    /// @param licenseTemplate License template address
    /// @param licenseTermsId License terms ID 
    function addGlobalWhitelistEntry(
        address parentIpId,
        address childIpId,
        address licenseTemplate,
        uint256 licenseTermsId
    ) external onlyOwner {
        _addToWhitelist({
            parentIpId: parentIpId,
            childIpId: childIpId,
            licensee: address(0),
            licenseTemplate: licenseTemplate,
            licenseTermsId: licenseTermsId
        });
    }

    /// @notice Convenience function to remove a global whitelist entry
    /// @param parentIpId Parent IP address
    /// @param childIpId Child/derivative IP address
    /// @param licenseTemplate License template address
    /// @param licenseTermsId License terms ID 
    function removeGlobalWhitelistEntry(
        address parentIpId,
        address childIpId,
        address licenseTemplate,
        uint256 licenseTermsId
    ) external onlyOwner {
        _removeFromWhitelist({
            parentIpId: parentIpId,
            childIpId: childIpId,
            licensee: address(0),
            licenseTemplate: licenseTemplate,
            licenseTermsId: licenseTermsId
        });
    }

    /// @notice Check if a licensee is whitelisted (exact match or wildcard)
    /// @param parentIpId Parent IP address
    /// @param childIpId Child/derivative IP address
    /// @param licenseTemplate License template address
    /// @param licenseTermsId License terms ID (must be non-zero)
    /// @param licensee Licensee address to check
    /// @return True if wildcard (address(0)) is whitelisted OR exact licensee is whitelisted
    function isWhitelisted(
        address parentIpId,
        address childIpId,
        address licenseTemplate,
        uint256 licenseTermsId,
        address licensee
    ) public view returns (bool) {
        // Check wildcard first (more general case)
        bytes32 keyWildcard = _whitelistKey(parentIpId, childIpId, licenseTemplate, licenseTermsId, address(0));
        if (_whitelist[keyWildcard]) return true;
        // Check specific licensee
        bytes32 keyExact = _whitelistKey(parentIpId, childIpId, licenseTemplate, licenseTermsId, licensee);
        return _whitelist[keyExact];
    }

    /// @notice Helper function to compute the whitelist key for off-chain use
    /// @param parentIpId Parent IP address
    /// @param childIpId Child/derivative IP address
    /// @param licenseTemplate License template address
    /// @param licenseTermsId License terms ID (must be non-zero)
    /// @param licensee Licensee address
    /// @return The computed whitelist key
    function getWhitelistKey(
        address parentIpId,
        address childIpId,
        address licenseTemplate,
        uint256 licenseTermsId,
        address licensee
    ) external pure returns (bytes32) {
        return _whitelistKey(parentIpId, childIpId, licenseTemplate, licenseTermsId, licensee);
    }

    /// @notice Helper function to return raw whitelist status by key
    /// @param key The whitelist key
    /// @return True if the key is whitelisted
    function getWhitelistStatusByKey(bytes32 key) external view returns (bool) {
        return _whitelist[key];
    }

    /// -----------------------------------------------------------------------
    /// Pausable Controls
    /// -----------------------------------------------------------------------

    /// @notice Pause the contract (blocks registerDerivativeViaAgent calls). Only callable by owner.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpause the contract. Only callable by owner.
    function unpause() external onlyOwner {
        _unpause();
    }

    /// -----------------------------------------------------------------------
    /// Derivative Registration (Delegated by Licensee)
    /// -----------------------------------------------------------------------

    /// @notice Register a derivative via IPDerivativeAgent
    /// @dev CRITICAL: The licensee (msg.sender) must have approved this agent to transfer
    ///      the minting fee token BEFORE calling this function. Use ERC20.approve(agentAddress, feeAmount).
    /// @dev The agent will:
    ///      1. Check whitelist authorization
    ///      2. Predict the minting fee
    ///      3. Validate fee against maxMintingFee (if specified)
    ///      4. Pull fee tokens from licensee
    ///      5. Approve RoyaltyModule to spend fee tokens
    ///      6. Call LicensingModule.registerDerivative
    ///      7. Clean up any remaining allowance
    /// @param childIpId The derivative IP ID (must be non-zero)
    /// @param parentIpId The parent IP ID (must be non-zero)
    /// @param licenseTermsId The license terms ID in the license template (must be non-zero)
    /// @param licenseTemplate The license template address (must be non-zero)
    /// @param maxMintingFee Maximum minting fee willing to pay. Use 0 for no limit (per LicensingModule conventions).
    function registerDerivativeViaAgent(
        address childIpId,
        address parentIpId,
        uint256 licenseTermsId,
        address licenseTemplate,
        uint256 maxMintingFee
    ) external nonReentrant whenNotPaused {
        if (childIpId == address(0) || parentIpId == address(0) || licenseTemplate == address(0) || licenseTermsId == 0) {
            revert IPDerivativeAgent_InvalidParams();
        }

        // Check whitelist (exact match or wildcard)
        if (!isWhitelisted(parentIpId, childIpId, licenseTemplate, licenseTermsId, msg.sender)) {
            revert IPDerivativeAgent_NotWhitelisted(parentIpId, childIpId, licenseTemplate, licenseTermsId, msg.sender);
        }

        bytes memory royaltyContext = "";

        // Predict minting fee for a single license token (amount = 1), receiver = msg.sender (licensee/derivative owner)
        (address currencyToken, uint256 tokenAmount) = LICENSING_MODULE.predictMintingLicenseFee(
            parentIpId,
            licenseTemplate,
            licenseTermsId,
            1,
            msg.sender,
            royaltyContext
        );

        // Validate fee against maxMintingFee if caller specified a non-zero maximum
        if (maxMintingFee != 0 && tokenAmount > maxMintingFee) {
            revert IPDerivativeAgent_FeeTooHigh(tokenAmount, maxMintingFee);
        }

        // Prepare arrays for LicensingModule call (single parent)
        address[] memory parents = new address[](1);
        parents[0] = parentIpId;
        uint256[] memory licenseTermsIds = new uint256[](1);
        licenseTermsIds[0] = licenseTermsId;
        uint32 maxRts = 0;
        uint32 maxRevenueShare = 0;

        // Handle token payment if required
        if (currencyToken != address(0) && tokenAmount > 0) {
            IERC20 token = IERC20(currencyToken);

            // Transfer tokens from licensee to this contract
            token.safeTransferFrom(msg.sender, address(this), tokenAmount);

            // Increase allowance for RoyaltyModule to pull tokens during registerDerivative
            token.safeIncreaseAllowance(ROYALTY_MODULE, tokenAmount);
        }

        // Call LicensingModule to register derivative
        // The RoyaltyModule will pull the minting fee tokens from this contract during this call
        LICENSING_MODULE.registerDerivative(
            childIpId,
            parents,
            licenseTermsIds,
            licenseTemplate,
            royaltyContext,
            maxMintingFee,
            maxRts,
            maxRevenueShare
        );

        // Clean up any remaining allowance for RoyaltyModule
        if (currencyToken != address(0) && tokenAmount > 0) {
            IERC20 token = IERC20(currencyToken);
            uint256 remainingAllowance = token.allowance(address(this), ROYALTY_MODULE);
            if (remainingAllowance > 0) {
                token.forceApprove(ROYALTY_MODULE, 0);
            }
        }

        emit DerivativeRegistered(
            msg.sender,
            childIpId,
            parentIpId,
            licenseTermsId,
            licenseTemplate,
            tokenAmount
        );
    }

    /// -----------------------------------------------------------------------
    /// Emergency Recovery
    /// -----------------------------------------------------------------------

    /// @notice Emergency withdraw of stuck ERC20 tokens. Only callable by owner while paused.
    /// @dev This function is only available when the contract is paused to prevent accidental
    ///      withdrawal during normal operations. Use pause() first, then call this function.
    /// @dev Native tokens are not supported as the protocol only uses ERC20 tokens for payments.
    /// @param token ERC20 token address (must be non-zero)
    /// @param to Destination address (must be non-zero and not this contract)
    /// @param amount Amount to transfer (in token's smallest unit)
    function emergencyWithdraw(address token, address to, uint256 amount) external onlyOwner whenPaused nonReentrant {
        if (token == address(0) || to == address(0) || to == address(this)) {
            revert IPDerivativeAgent_InvalidParams();
        }
        
        IERC20(token).safeTransfer(to, amount);
        
        emit EmergencyWithdraw(token, to, amount);
    }

    /// @dev internal helper to add a whitelist entry
    /// @param parentIpId Parent IP address (must be non-zero)
    /// @param childIpId Child/derivative IP address (must be non-zero)
    /// @param licensee Specific licensee address, or address(0) for wildcard
    /// @param licenseTemplate License template address (must be non-zero)
    /// @param licenseTermsId License terms ID (must be non-zero)
    function _addToWhitelist(
        address parentIpId,
        address childIpId,
        address licensee,
        address licenseTemplate,
        uint256 licenseTermsId
    ) internal {
        if (parentIpId == address(0) || childIpId == address(0) || licenseTemplate == address(0) || licenseTermsId == 0) {
            revert IPDerivativeAgent_InvalidParams();
        }

        bytes32 key = _whitelistKey(
            parentIpId, 
            childIpId, 
            licenseTemplate, 
            licenseTermsId, 
            licensee);

        if (_whitelist[key]) return;

        _whitelist[key] = true;

        emit WhitelistedAdded(
            parentIpId, 
            childIpId, 
            licenseTemplate, 
            licenseTermsId, 
            licensee
        );
    }

    /// @dev internal helper to remove a whitelist entry
    /// @param parentIpId Parent IP address (must be non-zero)
    /// @param childIpId Child/derivative IP address (must be non-zero)
    /// @param licensee Specific licensee address, or address(0) for wildcard
    /// @param licenseTemplate License template address (must be non-zero)
    /// @param licenseTermsId License terms ID (must be non-zero)
    function _removeFromWhitelist(
        address parentIpId,
        address childIpId,
        address licensee,
        address licenseTemplate,
        uint256 licenseTermsId
    ) internal {
        if (parentIpId == address(0) || childIpId == address(0) || licenseTemplate == address(0) || licenseTermsId == 0) {
            revert IPDerivativeAgent_InvalidParams();
        }

        bytes32 key = _whitelistKey(parentIpId, childIpId, licenseTemplate, licenseTermsId, licensee);
        if (!_whitelist[key]) {
            return;
        }
        _whitelist[key] = false;
        emit WhitelistedRemoved(parentIpId, childIpId, licenseTemplate, licenseTermsId, licensee);
    }

    /// @dev Compute whitelist key from parameters
    /// @param parentIpId Parent IP address
    /// @param childIpId Child/derivative IP address
    /// @param licenseTemplate License template address
    /// @param licenseTermsId License terms ID (must be non-zero)
    /// @param licensee Specific licensee address (or address(0) for wildcard)
    /// @return Keccak256 hash of the packed parameters
    function _whitelistKey(
        address parentIpId,
        address childIpId,
        address licenseTemplate,
        uint256 licenseTermsId,
        address licensee
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(parentIpId, childIpId, licenseTemplate, licenseTermsId, licensee));
    }
}