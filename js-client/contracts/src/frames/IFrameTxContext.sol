// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice ABI of the Yul `FrameTxContext` helper (yul/FrameTxContext.yul):
///         EIP-8141 TXPARAM / FRAMEPARAM / SIGPARAM / SIGDATACOPY behind a plain
///         interface, since solc cannot emit those opcodes from Solidity.
///         Every call halts when not executing inside a frame transaction.
interface IFrameTxContext {
    /// @notice TXPARAM(0x08): the frame tx's sig_hash — what empty-`msg` signatures sign.
    function sigHash() external view returns (bytes32);
    /// @notice TXPARAM(id).
    function txParam(uint256 id) external view returns (uint256);
    /// @notice FRAMEPARAM(frameIndex, param).
    function frameParam(uint256 frameIndex, uint256 param) external view returns (uint256);
    /// @notice SIGPARAM(sigIndex, param).
    function sigParam(uint256 sigIndex, uint256 param) external view returns (uint256);
    /// @notice Raw bytes of the ARBITRARY-scheme signature at `sigIndex` (SIGPARAM len + SIGDATACOPY).
    function signature(uint256 sigIndex) external view returns (bytes memory);
}

/// @dev TXPARAM ids (EIP-8141).
library TxParam {
    uint256 internal constant TX_TYPE = 0x00;
    uint256 internal constant NONCE = 0x01;
    uint256 internal constant SENDER = 0x02;
    uint256 internal constant SIG_HASH = 0x08;
    uint256 internal constant FRAMES_LENGTH = 0x09;
    uint256 internal constant CURRENT_FRAME_INDEX = 0x0A;
    uint256 internal constant SIGNATURES_LENGTH = 0x0B;
}
