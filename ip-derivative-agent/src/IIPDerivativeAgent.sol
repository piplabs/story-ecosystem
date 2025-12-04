// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IIPDerivativeAgent
/// @notice interface for the IPDerivativeAgent contract
interface IIPDerivativeAgent {
    /// @notice Struct to group whitelist parameters for safer batch operations
    /// @param parentIpId Parent IP address (must be non-zero)
    /// @param childIpId Child/derivative IP address (must be non-zero)
    /// @param licensee Specific licensee address, or address(0) for wildcard
    /// @param licenseTemplate License template address (must be non-zero)
    /// @param licenseTermsId License terms ID (must be non-zero)
    struct WhitelistEntry {
        address parentIpId;
        address childIpId;
        address licensee;
        address licenseTemplate;
        uint256 licenseTermsId;
    }

    /// @dev Custom errors for gas-efficient reverts
    error IPDerivativeAgent_ZeroAddress();
    error IPDerivativeAgent_AlreadyWhitelisted(
        address parentIpId,
        address childIpId,
        address licenseTemplate,
        uint256 licenseTermsId,
        address licensee
    );
    error IPDerivativeAgent_NotWhitelisted(
        address parentIpId,
        address childIpId,
        address licenseTemplate,
        uint256 licenseTermsId,
        address licensee
    );
    error IPDerivativeAgent_InvalidParams();
    error IPDerivativeAgent_FeeTooHigh(uint256 required, uint256 maxAllowed);
    error IPDerivativeAgent_EmergencyWithdrawFailed();
    error IPDerivativeAgent_TooManyEntries(uint256 entriesCount, uint256 maxEntries);

    /// @notice Emitted when a whitelist entry is added
    event WhitelistedAdded(
        address indexed parentIpId,
        address indexed childIpId,
        address indexed licenseTemplate,
        uint256 licenseTermsId,
        address licensee
    );

    /// @notice Emitted when a whitelist entry is removed
    event WhitelistedRemoved(
        address indexed parentIpId,
        address indexed childIpId,
        address indexed licenseTemplate,
        uint256 licenseTermsId,
        address licensee
    );

    /// @notice Emitted on successful derivative registration via agent
    event DerivativeRegistered(
        address indexed caller,
        address indexed childIpId,
        address indexed parentIpId,
        uint256 licenseTermsId,
        address licenseTemplate,
        address currencyToken,
        uint256 tokenAmount
    );

    /// @notice Emitted on emergency withdraw
    event EmergencyWithdraw(address indexed token, address indexed to, uint256 amount);

    /// -----------------------------------------------------------------------
    /// Whitelist Management
    /// -----------------------------------------------------------------------

    /// @notice Add a single whitelist entry. Callable by owner only.
    /// @dev Setting licensee = address(0) creates a global entry (any caller can register)
    /// @param entry the entry to whitelist
    function addToWhitelist(WhitelistEntry calldata entry) external;

    /// @notice Remove a single whitelist entry. Callable by owner only.
    /// @param entry the entry to remove from whitelist
    function removeFromWhitelist(WhitelistEntry calldata entry) external;

    /// @notice Batch add whitelist entries.
    /// @param entries Array of WhitelistEntry structs containing whitelist parameters
    function addToWhitelistBatch(WhitelistEntry[] calldata entries) external;

    /// @notice Batch remove whitelist entries.
    /// @param entries Array of WhitelistEntry structs containing whitelist parameters
    function removeFromWhitelistBatch(WhitelistEntry[] calldata entries) external;

    /// @notice Convenience function to add a global whitelist entry (allows any caller)
    /// @notice While a global whitelist entry is set, trying to whitelist only a specific caller won't work:
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
    ) external;

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
    ) external;

    /// @notice Check a licensee's whitelist status for a given set of
    /// parentIpId, childIpId, licenseTemplate, licenseTermsId (exact match or global entry)
    /// @param parentIpId Parent IP address
    /// @param childIpId Child/derivative IP address
    /// @param licenseTemplate License template address
    /// @param licenseTermsId License terms ID (must be non-zero)
    /// @param licensee Licensee address to check
    /// @return isWhitelisted True if global entry (address(0)) is whitelisted OR exact licensee is whitelisted
    function isLicenseeWhitelisted(
        address parentIpId,
        address childIpId,
        address licenseTemplate,
        uint256 licenseTermsId,
        address licensee
    ) external view returns (bool isWhitelisted);

    /// @notice View function computing a whitelist key
    /// @param parentIpId Parent IP address
    /// @param childIpId Child/derivative IP address
    /// @param licenseTemplate License template address
    /// @param licenseTermsId License terms ID (must be non-zero)
    /// @param licensee Licensee address
    /// @return whitelistKey The computed whitelist key
    function getWhitelistKey(
        address parentIpId,
        address childIpId,
        address licenseTemplate,
        uint256 licenseTermsId,
        address licensee
    ) external pure returns (bytes32 whitelistKey);

    /// @notice View function returning raw whitelist status by key
    /// @param key The whitelist key
    /// @return keyWhitelisted True if the key is whitelisted, else False
    function isKeyWhitelisted(bytes32 key) external view returns (bool keyWhitelisted);

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
    ) external;

    /// -----------------------------------------------------------------------
    /// Pausable Controls
    /// -----------------------------------------------------------------------

    /// @notice Pause the contract (blocks registerDerivativeViaAgent calls). Only callable by owner.
    function pause() external;

    /// @notice Unpause the contract. Only callable by owner.
    function unpause() external;

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
    function emergencyWithdraw(address token, address to, uint256 amount) external;
}
