// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { IPDerivativeAgent } from "../src/IPDerivativeAgent.sol";
import { IIPDerivativeAgent } from "../src/IIPDerivativeAgent.sol";
import { MockLicensingModule } from "../test/mocks/MockLicensingModule.sol";
import { MockERC20 } from "../test/mocks/MockERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";

contract IPDerivativeAgentTest is Test {
    IPDerivativeAgent public agent;
    MockLicensingModule public licensingModule;
    MockERC20 public token;

    address public owner = address(0x1);
    address public royaltyModule = address(0x2);
    address public parentIp = address(0x3);
    address public childIp = address(0x4);
    address public licenseTemplate = address(0x5);
    address public licensee = address(0x6);
    uint256 public licenseTermsId = 1;

    IIPDerivativeAgent.WhitelistEntry public sampleEntry =
        IIPDerivativeAgent.WhitelistEntry({
            parentIpId: parentIp,
            childIpId: childIp,
            licensee: licensee,
            licenseTemplate: licenseTemplate,
            licenseTermsId: licenseTermsId
        });

    IIPDerivativeAgent.WhitelistEntry public globalEntry =
        IIPDerivativeAgent.WhitelistEntry({
            parentIpId: parentIp,
            childIpId: childIp,
            licensee: address(0),
            licenseTemplate: licenseTemplate,
            licenseTermsId: licenseTermsId
        });

    function setUp() public {
        // Deploy mocks
        licensingModule = new MockLicensingModule();
        token = new MockERC20("Mock Token", "MTK");

        // Deploy agent
        vm.prank(owner);
        agent = new IPDerivativeAgent(owner, address(licensingModule), royaltyModule);

        // Mint tokens to licensee
        token.mint(licensee, 1000 ether);
    }

    // ========== Constructor Tests ==========

    function test_Constructor_Success() public view {
        assertEq(address(agent.LICENSING_MODULE()), address(licensingModule));
        assertEq(agent.ROYALTY_MODULE(), royaltyModule);
        assertEq(agent.owner(), owner);
    }

    function test_Constructor_RevertIf_ZeroLicensingModule() public {
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_ZeroAddress.selector);
        new IPDerivativeAgent(owner, address(0), royaltyModule);
    }

    function test_Constructor_RevertIf_ZeroRoyaltyModule() public {
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_ZeroAddress.selector);
        new IPDerivativeAgent(owner, address(licensingModule), address(0));
    }

    function test_Constructor_RevertIf_ZeroOwner() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
        new IPDerivativeAgent(address(0), address(licensingModule), royaltyModule);
    }

    // ========== Whitelist Management Tests ==========

    function test_AddToWhitelist_Success() public {
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit IIPDerivativeAgent.WhitelistedAdded(parentIp, childIp, licenseTemplate, licenseTermsId, licensee);
        agent.addToWhitelist(sampleEntry);

        assertTrue(agent.isLicenseeWhitelisted(parentIp, childIp, licenseTemplate, licenseTermsId, licensee));
    }

    function test_AddToWhitelist_RevertIf_NotOwner() public {
        vm.prank(address(0x999));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(0x999)));
        agent.addToWhitelist(sampleEntry);
    }

    function test_AddToWhitelist_RevertIf_ZeroParentIp() public {
        IIPDerivativeAgent.WhitelistEntry memory entry = sampleEntry;
        entry.parentIpId = address(0);
        vm.prank(owner);
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.addToWhitelist(entry);
    }

    function test_AddToWhitelist_RevertIf_ZeroChildIp() public {
        IIPDerivativeAgent.WhitelistEntry memory entry = sampleEntry;
        entry.childIpId = address(0);
        vm.prank(owner);
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.addToWhitelist(entry);
    }

    function test_AddToWhitelist_RevertIf_ZeroLicenseTemplate() public {
        IIPDerivativeAgent.WhitelistEntry memory entry = sampleEntry;
        entry.licenseTemplate = address(0);
        vm.prank(owner);
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.addToWhitelist(entry);
    }

    function test_AddToWhitelist_RevertIf_ZeroLicenseId() public {
        IIPDerivativeAgent.WhitelistEntry memory entry = sampleEntry;
        entry.licenseTermsId = 0;
        vm.prank(owner);
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.addToWhitelist(entry);
    }

    function test_AddToWhitelist_AlreadyWhitelisted_shouldNotRevert() public {
        vm.startPrank(owner);

        agent.addToWhitelist(sampleEntry);
        assertTrue(agent.isLicenseeWhitelisted(parentIp, childIp, licenseTemplate, licenseTermsId, licensee));

        agent.addToWhitelist(sampleEntry);
        assertTrue(agent.isLicenseeWhitelisted(parentIp, childIp, licenseTemplate, licenseTermsId, licensee));
        vm.stopPrank();
    }

    function test_AddGlobalWhitelistEntry_Success() public {
        vm.prank(owner);
        agent.addToWhitelist(globalEntry);

        assertTrue(agent.isLicenseeWhitelisted(parentIp, childIp, licenseTemplate, licenseTermsId, address(0x999)));
        assertTrue(agent.isLicenseeWhitelisted(parentIp, childIp, licenseTemplate, licenseTermsId, licensee));
    }

    function test_RemoveFromWhitelist_Success() public {
        vm.startPrank(owner);
        agent.addToWhitelist(sampleEntry);
        agent.removeFromWhitelist(sampleEntry);
        vm.stopPrank();

        assertFalse(agent.isLicenseeWhitelisted(parentIp, childIp, licenseTemplate, licenseTermsId, licensee));
    }

    function test_RemoveFromWhitelist_RevertIf_ZeroLicenseTermsId() public {
        vm.startPrank(owner);
        agent.addToWhitelist(sampleEntry);

        IIPDerivativeAgent.WhitelistEntry memory entry = sampleEntry;
        entry.licenseTermsId = 0;
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.removeFromWhitelist(entry);
        vm.stopPrank();
    }

    function test_RemoveFromWhitelist_RevertIf_ZeroParentIp() public {
        vm.startPrank(owner);
        agent.addToWhitelist(sampleEntry);

        IIPDerivativeAgent.WhitelistEntry memory entry = sampleEntry;
        entry.parentIpId = address(0);
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.removeFromWhitelist(entry);
        vm.stopPrank();
    }

    function test_RemoveFromWhitelist_RevertIf_ZeroChildIp() public {
        vm.startPrank(owner);
        agent.addToWhitelist(sampleEntry);

        IIPDerivativeAgent.WhitelistEntry memory entry = sampleEntry;
        entry.childIpId = address(0);
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.removeFromWhitelist(entry);
        vm.stopPrank();
    }

    function test_RemoveFromWhitelist_RevertIf_ZeroLicenseTemplate() public {
        vm.startPrank(owner);
        agent.addToWhitelist(sampleEntry);

        IIPDerivativeAgent.WhitelistEntry memory entry = sampleEntry;
        entry.licenseTemplate = address(0);
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.removeFromWhitelist(entry);
        vm.stopPrank();
    }

    function test_RemoveFromWhitelist_NotWhitelisted_shouldNotRevert() public {
        vm.startPrank(owner);
        agent.removeFromWhitelist(sampleEntry);
        vm.stopPrank();
    }

    function test_RemoveGlobalWhitelistEntry_Success() public {
        vm.startPrank(owner);

        agent.addToWhitelist(globalEntry);

        vm.expectEmit(true, true, true, true);
        emit IIPDerivativeAgent.WhitelistedRemoved(parentIp, childIp, licenseTemplate, licenseTermsId, address(0));
        agent.removeGlobalWhitelistEntry(parentIp, childIp, licenseTemplate, licenseTermsId);
        vm.stopPrank();

        assertFalse(agent.isLicenseeWhitelisted(parentIp, childIp, licenseTemplate, licenseTermsId, address(0x999)));
        assertFalse(agent.isLicenseeWhitelisted(parentIp, childIp, licenseTemplate, licenseTermsId, licensee));
    }

    function test_BatchAddToWhitelist_Success() public {
        IIPDerivativeAgent.WhitelistEntry[] memory entries = new IIPDerivativeAgent.WhitelistEntry[](2);

        entries[0] = sampleEntry;

        entries[1] = IIPDerivativeAgent.WhitelistEntry({
            parentIpId: address(0x10),
            childIpId: address(0x11),
            licensee: address(0x12),
            licenseTemplate: address(0x13),
            licenseTermsId: 2
        });

        vm.prank(owner);
        agent.addToWhitelistBatch(entries);

        assertTrue(
            agent.isLicenseeWhitelisted(
                entries[0].parentIpId,
                entries[0].childIpId,
                entries[0].licenseTemplate,
                entries[0].licenseTermsId,
                entries[0].licensee
            )
        );
        assertTrue(
            agent.isLicenseeWhitelisted(
                entries[1].parentIpId,
                entries[1].childIpId,
                entries[1].licenseTemplate,
                entries[1].licenseTermsId,
                entries[1].licensee
            )
        );
    }

    function test_BatchAddToWhitelist_RevertIf_TooManyEntries() public {
        uint256 tooMany = agent.MAX_ENTRIES() + 1;
        IIPDerivativeAgent.WhitelistEntry[] memory entries = new IIPDerivativeAgent.WhitelistEntry[](tooMany);

        for (uint256 i = 0; i < tooMany; ++i) {
            entries[i] = IIPDerivativeAgent.WhitelistEntry({
                parentIpId: address(uint160(0x10 + i)),
                childIpId: address(uint160(0x20 + i)),
                licensee: address(uint160(0x30 + i)),
                licenseTemplate: address(uint160(0x40 + i)),
                licenseTermsId: 1
            });
        }

        vm.startPrank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(
                IIPDerivativeAgent.IPDerivativeAgent_TooManyEntries.selector,
                agent.MAX_ENTRIES() + 1,
                agent.MAX_ENTRIES()
            )
        );
        agent.addToWhitelistBatch(entries);
        vm.stopPrank();
    }

    function test_BatchAddToWhitelist_RevertIf_ZeroLicenseTermsId() public {
        IIPDerivativeAgent.WhitelistEntry[] memory entries = new IIPDerivativeAgent.WhitelistEntry[](2);

        entries[0] = sampleEntry;

        entries[1] = IIPDerivativeAgent.WhitelistEntry({
            parentIpId: address(0x10),
            childIpId: address(0x11),
            licensee: address(0x12),
            licenseTemplate: address(0x13),
            licenseTermsId: 0 // Zero license terms ID
        });

        vm.prank(owner);
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.addToWhitelistBatch(entries);
    }

    function test_BatchRemoveFromWhitelist_Success() public {
        IIPDerivativeAgent.WhitelistEntry[] memory entries = new IIPDerivativeAgent.WhitelistEntry[](2);

        entries[0] = sampleEntry;

        entries[1] = IIPDerivativeAgent.WhitelistEntry({
            parentIpId: address(0x10),
            childIpId: address(0x11),
            licensee: address(0x12),
            licenseTemplate: address(0x13),
            licenseTermsId: 2
        });

        vm.startPrank(owner);
        // Add entries first
        agent.addToWhitelistBatch(entries);

        // Remove entries
        agent.removeFromWhitelistBatch(entries);
        vm.stopPrank();

        // Verify removed
        assertFalse(
            agent.isLicenseeWhitelisted(
                entries[0].parentIpId,
                entries[0].childIpId,
                entries[0].licenseTemplate,
                entries[0].licenseTermsId,
                entries[0].licensee
            )
        );
        assertFalse(
            agent.isLicenseeWhitelisted(
                entries[1].parentIpId,
                entries[1].childIpId,
                entries[1].licenseTemplate,
                entries[1].licenseTermsId,
                entries[1].licensee
            )
        );
    }

    function test_BatchRemoveFromWhitelist_RevertIf_ZeroLicenseTermsId() public {
        IIPDerivativeAgent.WhitelistEntry[] memory addEntries = new IIPDerivativeAgent.WhitelistEntry[](2);
        IIPDerivativeAgent.WhitelistEntry[] memory removeEntries = new IIPDerivativeAgent.WhitelistEntry[](2);

        addEntries[0] = sampleEntry;

        addEntries[1] = IIPDerivativeAgent.WhitelistEntry({
            parentIpId: address(0x10),
            childIpId: address(0x11),
            licensee: address(0x12),
            licenseTemplate: address(0x13),
            licenseTermsId: 2
        });

        removeEntries[0] = addEntries[0];
        removeEntries[1] = IIPDerivativeAgent.WhitelistEntry({
            parentIpId: address(0x10),
            childIpId: address(0x11),
            licensee: address(0x12),
            licenseTemplate: address(0x13),
            licenseTermsId: 0 // Zero license terms ID
        });

        vm.startPrank(owner);
        // Add entries first
        agent.addToWhitelistBatch(addEntries);

        // Try to remove with zero license terms ID
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.removeFromWhitelistBatch(removeEntries);
        vm.stopPrank();
    }

    function test_BatchRemoveFromWhitelist_RevertIf_TooManyEntries() public {
        uint256 tooMany = agent.MAX_ENTRIES() + 1;
        IIPDerivativeAgent.WhitelistEntry[] memory entries = new IIPDerivativeAgent.WhitelistEntry[](tooMany);

        for (uint256 i = 0; i < tooMany; ++i) {
            entries[i] = IIPDerivativeAgent.WhitelistEntry({
                parentIpId: address(uint160(0x10 + i)),
                childIpId: address(uint160(0x20 + i)),
                licensee: address(uint160(0x30 + i)),
                licenseTemplate: address(uint160(0x40 + i)),
                licenseTermsId: 1
            });
        }

        vm.startPrank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(
                IIPDerivativeAgent.IPDerivativeAgent_TooManyEntries.selector,
                agent.MAX_ENTRIES() + 1,
                agent.MAX_ENTRIES()
            )
        );
        agent.removeFromWhitelistBatch(entries);
        vm.stopPrank();
    }

    // ========== Registration Tests ==========

    function test_RegisterDerivative_Success_WithFee() public {
        uint256 fee = 10 ether;
        licensingModule.setMintingFee(address(token), fee);

        // Whitelist the licensee
        vm.prank(owner);
        agent.addToWhitelist(sampleEntry);

        // Approve agent to spend tokens
        vm.prank(licensee);
        token.approve(address(agent), fee);

        // Register derivative
        vm.prank(licensee);
        vm.expectEmit(true, true, true, true);
        emit IIPDerivativeAgent.DerivativeRegistered(
            licensee,
            childIp,
            parentIp,
            licenseTermsId,
            licenseTemplate,
            address(token),
            fee
        );
        agent.registerDerivativeViaAgent(childIp, parentIp, licenseTermsId, licenseTemplate, 0);

        // Check that tokens were transferred
        assertEq(token.balanceOf(licensee), 1000 ether - fee);
    }

    function test_RegisterDerivative_Success_NoFee() public {
        licensingModule.setMintingFee(address(0), 0);

        // Whitelist the licensee
        vm.prank(owner);
        agent.addToWhitelist(sampleEntry);

        // Register derivative
        vm.prank(licensee);
        agent.registerDerivativeViaAgent(childIp, parentIp, licenseTermsId, licenseTemplate, 0);

        // Check that no tokens were transferred
        assertEq(token.balanceOf(licensee), 1000 ether);
    }

    function test_RegisterDerivative_Success_WithGlobalEntry() public {
        uint256 fee = 5 ether;
        licensingModule.setMintingFee(address(token), fee);

        // Whitelist with global entry
        vm.prank(owner);
        agent.addToWhitelist(globalEntry);

        // Any address can register now
        address anyAddress = address(0x999);
        token.mint(anyAddress, 100 ether);

        vm.startPrank(anyAddress);
        token.approve(address(agent), fee);
        agent.registerDerivativeViaAgent(childIp, parentIp, licenseTermsId, licenseTemplate, 0);
        vm.stopPrank();

        assertEq(token.balanceOf(anyAddress), 100 ether - fee);
    }

    function test_RegisterDerivative_RevertIf_NotWhitelisted() public {
        vm.prank(licensee);
        vm.expectRevert(
            abi.encodeWithSelector(
                IIPDerivativeAgent.IPDerivativeAgent_NotWhitelisted.selector,
                parentIp,
                childIp,
                licenseTemplate,
                licenseTermsId,
                licensee
            )
        );
        agent.registerDerivativeViaAgent(childIp, parentIp, licenseTermsId, licenseTemplate, 0);
    }

    function test_RegisterDerivative_RevertIf_FeeTooHigh() public {
        uint256 fee = 10 ether;
        uint256 maxFee = 5 ether;
        licensingModule.setMintingFee(address(token), fee);

        vm.prank(owner);
        agent.addToWhitelist(sampleEntry);

        vm.prank(licensee);
        token.approve(address(agent), fee);

        vm.prank(licensee);
        vm.expectRevert(abi.encodeWithSelector(IIPDerivativeAgent.IPDerivativeAgent_FeeTooHigh.selector, fee, maxFee));
        agent.registerDerivativeViaAgent(childIp, parentIp, licenseTermsId, licenseTemplate, maxFee);
    }

    function test_RegisterDerivative_RevertIf_Paused() public {
        vm.prank(owner);
        agent.addToWhitelist(sampleEntry);

        vm.prank(owner);
        agent.pause();

        vm.prank(licensee);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        agent.registerDerivativeViaAgent(childIp, parentIp, licenseTermsId, licenseTemplate, 0);
    }

    function test_RegisterDerivative_RevertIf_ZeroLicenseTermsId() public {
        vm.prank(owner);
        agent.addToWhitelist(sampleEntry);

        vm.prank(licensee);
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.registerDerivativeViaAgent(childIp, parentIp, 0, licenseTemplate, 0);
    }

    function test_RegisterDerivative_RevertIf_ZeroChildIpId() public {
        vm.prank(owner);
        agent.addToWhitelist(sampleEntry);

        vm.prank(licensee);
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.registerDerivativeViaAgent(address(0), parentIp, licenseTermsId, licenseTemplate, 0);
    }

    function test_RegisterDerivative_RevertIf_ZeroParentIpId() public {
        vm.prank(owner);
        agent.addToWhitelist(sampleEntry);

        vm.prank(licensee);
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.registerDerivativeViaAgent(childIp, address(0), licenseTermsId, licenseTemplate, 0);
    }

    function test_RegisterDerivative_RevertIf_ZeroLicenseTemplate() public {
        vm.prank(owner);
        agent.addToWhitelist(sampleEntry);

        vm.prank(licensee);
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.registerDerivativeViaAgent(childIp, parentIp, licenseTermsId, address(0), 0);
    }

    // ========== Pausable Tests ==========

    function test_Pause_Success() public {
        vm.prank(owner);
        agent.pause();
        assertTrue(agent.paused());
    }

    function test_Unpause_Success() public {
        vm.startPrank(owner);
        agent.pause();
        agent.unpause();
        vm.stopPrank();
        assertFalse(agent.paused());
    }

    function test_Pause_RevertIf_NotOwner() public {
        vm.prank(address(0x999));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(0x999)));
        agent.pause();
    }

    // ========== Emergency Withdraw Tests ==========

    function test_EmergencyWithdraw_Success() public {
        // Send tokens to agent
        token.mint(address(agent), 100 ether);

        vm.startPrank(owner);
        agent.pause();
        agent.emergencyWithdraw(address(token), owner, 100 ether);
        vm.stopPrank();

        assertEq(token.balanceOf(owner), 100 ether);
        assertEq(token.balanceOf(address(agent)), 0);
    }

    function test_EmergencyWithdraw_RevertIf_ZeroToken() public {
        vm.startPrank(owner);
        agent.pause();
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.emergencyWithdraw(address(0), owner, 10 ether);
        vm.stopPrank();
    }

    function test_EmergencyWithdraw_RevertIf_NotPaused() public {
        token.mint(address(agent), 100 ether);

        vm.prank(owner);
        vm.expectRevert(Pausable.ExpectedPause.selector);
        agent.emergencyWithdraw(address(token), owner, 100 ether);
    }

    function test_EmergencyWithdraw_RevertIf_ToIsContract() public {
        token.mint(address(agent), 100 ether);

        vm.startPrank(owner);
        agent.pause();
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.emergencyWithdraw(address(token), address(agent), 100 ether);
        vm.stopPrank();
    }

    function test_EmergencyWithdraw_RevertIf_CallerNotOwner() public {
        token.mint(address(agent), 100 ether);

        vm.startPrank(owner);
        agent.pause();
        vm.expectRevert(IIPDerivativeAgent.IPDerivativeAgent_InvalidParams.selector);
        agent.emergencyWithdraw(address(token), address(0), 100 ether);
        vm.stopPrank();
    }

    function test_EmergencyWithdraw_RevertIf_ToIsZeroAddress() public {
        token.mint(address(agent), 100 ether);

        vm.prank(owner);
        agent.pause();
        vm.prank(address(0x999));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(0x999)));
        agent.emergencyWithdraw(address(token), address(0), 100 ether);
        vm.stopPrank();
    }

    // ========== View Functions Tests ==========

    function test_GetWhitelistKey() public view {
        bytes32 key = agent.getWhitelistKey(parentIp, childIp, licenseTemplate, licenseTermsId, licensee);
        assertEq(key, keccak256(abi.encodePacked(parentIp, childIp, licenseTemplate, licenseTermsId, licensee)));
    }

    function test_IsKeyWhitelisted() public {
        vm.prank(owner);
        agent.addToWhitelist(sampleEntry);

        bytes32 key = agent.getWhitelistKey(parentIp, childIp, licenseTemplate, licenseTermsId, licensee);
        assertTrue(agent.isKeyWhitelisted(key));
    }
}
