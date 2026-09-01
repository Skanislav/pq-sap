// SPDX-License-Identifier: MIT
//
// FrameTxContext — EIP-8141 frame-transaction context reads, callable from Solidity.
//
// solc cannot emit the new opcodes (TXPARAM 0xB0, FRAMEPARAM 0xB3, SIGPARAM 0xB4,
// SIGDATACOPY 0xB5) from Solidity source, so this tiny stateless contract wraps them
// with `verbatim` and an ordinary ABI. The opcodes read the *transaction* context and
// work at any call depth (ethrex levm `opcode_handlers/frame_tx.rs`), so a STATICCALL
// from an account contract sees the same values the frame target itself would.
// Outside a frame transaction every entry point halts exceptionally (the opcodes do).
//
// Lives in contracts/yul/ (forge would try to parse it as Solidity under src/).
// Build: contracts/script/build-yul.sh (solc --strict-assembly).
//
//   sigHash()                       -> bytes32   TXPARAM(0x08): the digest empty-`msg` signatures sign
//   txParam(uint256 id)             -> uint256   TXPARAM(id)
//   frameParam(uint256 i, uint256 p)-> uint256   FRAMEPARAM(i, p)
//   sigParam(uint256 i, uint256 p)  -> uint256   SIGPARAM(i, p)   (p=3: byte length, ARBITRARY only)
//   signature(uint256 i)            -> bytes     raw bytes of the ARBITRARY signature at index i
//
// verbatim argument order follows Yul builtins: the first argument ends up on top of
// the stack, matching the "top first" operand lists in the ethrex handlers.
object "FrameTxContext" {
  code {
    datacopy(0, dataoffset("runtime"), datasize("runtime"))
    return(0, datasize("runtime"))
  }
  object "runtime" {
    code {
      switch shr(224, calldataload(0))
      case 0x6d24359b { // sigHash()
        mstore(0, verbatim_1i_1o(hex"b0", 8))
        return(0, 32)
      }
      case 0x16525c7f { // txParam(uint256)
        mstore(0, verbatim_1i_1o(hex"b0", calldataload(4)))
        return(0, 32)
      }
      case 0xff846610 { // frameParam(uint256,uint256)
        mstore(0, verbatim_2i_1o(hex"b3", calldataload(4), calldataload(36)))
        return(0, 32)
      }
      case 0xf457766f { // sigParam(uint256,uint256)
        mstore(0, verbatim_2i_1o(hex"b4", calldataload(4), calldataload(36)))
        return(0, 32)
      }
      case 0x70629548 { // signature(uint256) returns (bytes)
        let index := calldataload(4)
        let len := verbatim_2i_1o(hex"b4", index, 3)
        mstore(0, 0x20)
        mstore(0x20, len)
        // SIGDATACOPY(memOffset, dataOffset, length, signatureIndex)
        verbatim_4i_0o(hex"b5", 0x40, 0, len, index)
        return(0, add(0x40, and(add(len, 31), not(31))))
      }
      default { revert(0, 0) }
    }
  }
}
