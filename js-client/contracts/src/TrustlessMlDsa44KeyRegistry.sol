// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {PKContract} from "ethdilithium/ZKNOX_PKContract.sol";
import {CtxShake, shakeUpdate, shakeDigest} from "ethdilithium/ZKNOX_shake.sol";
import {bitUnpackAtOffset, q} from "ethdilithium/ZKNOX_dilithium_utils.sol";
import {shake128Init, shake128SqueezeBlock, Shake128Ctx} from "./Shake128.sol";
import {IMlDsa44ExpandedKeys} from "./MlDsa44KeyRegistry.sol";

/// @title TrustlessMlDsa44KeyRegistry
/// @notice Key setup for the `ml-dsa-44-commit/v0` profile with NO trusted
///         party: `aHat = ExpandA(rho)` is computed ON CHAIN, one matrix entry
///         per transaction, so no registrar (and no one else) can influence
///         which matrix the verifier uses for a given `pk` — the acceptance
///         criterion of #27. The one-transaction trusted alternative is
///         `TrustedMlDsa44KeyRegistry`; this is the staged route the issue
///         lists first, trading 18 transactions (17 of them SHAKE-heavy)
///         for the removal of the registrar trust.
///
///         It exposes the same `IMlDsa44ExpandedKeys` interface, so the
///         signer, adapter and factory CODE are unchanged and need no fork.
///         The deployed instances are not: `MlDsa44CommitSigner7913.KEYS`
///         is immutable, so this registry needs its own signer/adapter/
///         factory instances, and therefore its own counterfactual account
///         addresses. Funds already sitting at an address derived from a
///         trusted-registry factory cannot be migrated to this route
///         (docs/ml-dsa-commit-profile.md §4).
///         It deliberately does NOT implement `register`/`replace`:
///         there is nothing to attest and nothing to correct.
///
///         Staging. ExpandA is 16 independent streams: for each entry (i,j)
///         of the 4x4 public matrix, FIPS 204 samples the NTT-domain polynomial
///         by rejection sampling from SHAKE128(rho || j || i) — 3-byte
///         little-endian chunks, masked to 23 bits, rejecting values >= q,
///         until 256 coefficients are accepted (~771 bytes, 5 squeeze blocks,
///         worst case measured over the fixture key). `stage(pk, entryIndex)`
///         expands one entry and stores ONLY `keccak256(words)` of it — one
///         SSTORE instead of 32 cold ones; the words themselves never touch
///         storage. `finalize(pk, flatWords)` takes the 512 words as calldata
///         (flat: entry e at flatWords[32*e]; they are a pure function of
///         the pinned rho, recomputable by anyone off chain — Python/TS
///         ExpandA) and checks each entry
///         against its stored hash, so the hash pins the assembled matrix
///         exactly as tightly as storing the words would: only the staged
///         values themselves can pass, and a stager's word set cannot be
///         substituted. Entries may be staged in any order, by anyone, each
///         exactly once (a repeat stage of an already-done entry is a no-op,
///         so a 16-stage bundle cannot be invalidated by a front-runner or a
///         racing helper that staged one entry first). `finalize` deploys the
///         `PKContract` once all 16 are present, re-deriving `tr` and `t1`
///         from the canonical key bytes exactly as the trusted registry does.
///         Measured on the fixture key (forge 1.4.1, the CI pin), fair
///         harness (argument marshalling outside the measured window):
///         2,448,986 per stage (was 3,134,694 with per-word storage — the
///         32 cold SSTOREs it no longer pays, ~686 k per entry) and
///         ≈ 10,990,434 finalize. The redesign's saving is all staging-side:
///         registry-side finalize actually drops ~1 M (the 512 cold SLOADs
///         become 16 calldata reads + hash checks), but the finalize
///         transaction itself must now carry the 16,384 bytes of words as
///         calldata, which costs the ~1.09 M that makes finalize a wash
///         end-to-end (measured 10,904,074 old vs 10,990,434 new on the
///         same harness). Net across the whole 18-tx flow:
///         ≈ 10.9 M saved and 16 storage slots of state instead of 512.
///
///         Trustlessness. `rho` is pinned at `begin` and the full `pk` is
///         hash-checked at every step, so a caller can only feed the committed
///         key's own rho; the matrix is then a pure function of `rho`. A
///         racing stager cannot alter the result — they can only precompute
///         what the deterministic function will output. There is no privileged
///         and no replacement path; the PKContract address is CREATE2-
///         deterministic in (this registry, pk) with salt zero. The whole
///         flow is 18 transactions (begin + 16 stages + finalize), 17 of
///         which do SHAKE work.
contract TrustlessMlDsa44KeyRegistry is IMlDsa44ExpandedKeys {
    uint256 public constant PUBLIC_KEY_LENGTH = 1312;
    uint256 internal constant K = 4;
    uint256 internal constant L = 4;
    uint256 internal constant N = 256;
    uint256 internal constant T1_BITS = 10;
    uint256 internal constant TR_LENGTH = 64;
    uint256 internal constant ENTRIES = 16;

    struct Setup {
        bytes32 rho; // pk[0:32], pinned at begin
        bool started;
        uint16 done; // bitmap of expanded entries (bit e = entry e)
    }

    mapping(bytes32 pkHash => Setup) public setups;
    /// @dev Per-entry commitment: `keccak256(abi.encodePacked(words))` of the 32
    ///      compact_256(32) words the on-chain ExpandA produced for that
    ///      entry. The words themselves never touch storage; `finalize`
    ///      re-receives them as calldata (anyone can recompute them from the
    ///      pinned rho) and checks them against these hashes — 1 SSTORE per
    ///      entry instead of 32, and the hash pins the assembled matrix just
    ///      as tightly: only the exact staged values can pass.
    mapping(bytes32 pkHash => mapping(uint256 entry => bytes32)) public entryHashes;
    mapping(bytes32 pkHash => address) private _pointers;

    event SetupStarted(bytes32 indexed pkHash, bytes32 rho);
    event EntryExpanded(bytes32 indexed pkHash, uint256 entryIndex, address indexed by);
    event SetupFinalized(bytes32 indexed pkHash, address pointer);

    error BadKeyLength(uint256 length);
    error AlreadyFinalized(bytes32 pkHash);
    error BadEntryIndex(uint256 given);
    error NotStarted(bytes32 pkHash);
    error NotFinished(bytes32 pkHash, uint256 done);
    /// @dev Unreachable without a keccak256 collision (the setup is keyed by
    ///      `keccak256(pk)` AND pins rho); kept as defence-in-depth so a
    ///      mismatched rho fails loudly instead of aliasing a live setup.
    error RhoMismatch(bytes32 pinned, bytes32 given);
    /// @dev The calldata words for `entryIndex` do not hash to the stored
    ///      per-entry commitment. Can only fire on a caller that did not
    ///      stage ExpandA(rho) honestly (or did not recompute it faithfully).
    error EntryWordsMismatch(uint256 entryIndex, bytes32 stored, bytes32 given);

    /// @notice Start the staged expansion of `pk`. Idempotent; callable by
    ///         anyone (the matrix is a pure function of the key, so there is
    ///         nothing an initiator can influence).
    function begin(bytes calldata pk) external {
        if (pk.length != PUBLIC_KEY_LENGTH) revert BadKeyLength(pk.length);
        bytes32 pkHash = keccak256(pk);
        if (setups[pkHash].started) return; // idempotent
        setups[pkHash].rho = bytes32(pk[0:32]);
        setups[pkHash].started = true;
        emit SetupStarted(pkHash, setups[pkHash].rho);
    }

    /// @notice Expand matrix entry `entryIndex` (row i = e/4, col j = e%4)
    ///         from the pinned rho of the setup for `pk`. Anyone may call;
    ///         entries may be staged in any order, each exactly once — a
    ///         repeat stage of an already-expanded entry is a NO-OP (like
    ///         `begin`), so a 16-stage bundle cannot be invalidated by a
    ///         front-runner or a racing helper that got one entry in first.
    function stage(bytes calldata pk, uint256 entryIndex) external {
        bytes32 pkHash = keccak256(pk);
        Setup storage s = setups[pkHash];
        if (!s.started) revert NotStarted(pkHash);
        if (pk.length != PUBLIC_KEY_LENGTH) revert BadKeyLength(pk.length);
        if (bytes32(pk[0:32]) != s.rho) revert RhoMismatch(s.rho, bytes32(pk[0:32]));
        if (entryIndex >= ENTRIES) revert BadEntryIndex(entryIndex);
        if ((s.done >> entryIndex) & 1 == 1) return; // idempotent, like begin

        uint256 i = entryIndex / L;
        uint256 j = entryIndex % L;
        bytes memory seed = abi.encodePacked(s.rho, uint8(j), uint8(i));

        // rejection-sample 256 coefficients from SHAKE128(rho||j||i), pulling
        // squeeze blocks lazily so the stream can never run short (~771 bytes,
        // 5 blocks worst case over the fixture key; the loop adapts to any rho).
        // SHAKE128_RATE = 168 = 56 chunks of 3 bytes, so p stays a multiple of
        // 3 and a chunk never straddles two squeeze blocks — the loop below
        // RELIES on SHAKE128_RATE % 3 == 0 (136, the SHAKE256 rate, would
        // silently drop straddling chunk bytes).
        uint256[32] memory words;
        {
            Shake128Ctx memory xof = shake128Init(seed);
            bytes memory blockBytes = new bytes(0);
            uint256 p = 0; // consumed bytes of the current block
            uint256 have = 0;
            while (have < N) {
                if (p + 3 > blockBytes.length) {
                    (xof, blockBytes) = shake128SqueezeBlock(xof);
                    p = 0;
                }
                uint256 c = (uint256(uint8(blockBytes[p]))
                    | (uint256(uint8(blockBytes[p + 1])) << 8)
                    | (uint256(uint8(blockBytes[p + 2])) << 16)) & 0x7fffff;
                p += 3;
                if (c < q) {
                    words[have >> 3] |= c << (32 * (have & 7));
                    have += 1;
                }
            }
        }

        // ONE SSTORE: commit to the entry's words by hash. The words are a
        // deterministic function of the pinned rho, so finalize can demand
        // them back as calldata and check this hash — storage cost drops
        // from 32 cold SSTOREs to 1 with no loss of binding tightness.
        // NOTE: abi.encodePacked of a flat uint256 array is the raw
        // concatenated 32-byte words; _assemble hashes the dynamic-array
        // copy with the SAME encodePacked, so fixed-vs-dynamic encoding
        // differences cannot desynchronize the two sites.
        entryHashes[pkHash][entryIndex] = keccak256(abi.encodePacked(words));
        s.done = s.done | uint16(uint256(1) << entryIndex);
        emit EntryExpanded(pkHash, entryIndex, msg.sender);
    }

    /// @notice Finish: check the 16 entry word-sets (calldata, recomputable
    ///         by anyone from the pinned rho — Python/TS ExpandA) against
    ///         the stored per-entry hashes, re-derive `tr` and `t1` from the
    ///         key bytes, deploy the PKContract. Callable once; salt zero
    ///         (the binding is a pure function of pk — there is no freedom
    ///         left for anyone to exploit, and no replace path is needed).
    ///         `flatWords` is the 512 words of ExpandA flattened row-major
    ///         by entry: words of entry e occupy `flatWords[32*e .. 32*e+31]`,
    ///         entry e = row e/4, col e%4. (A flat array keeps the ABI
    ///         decoder trivial — a nested uint256[32][16] calldata argument
    ///         overflows the legacy-codegen stack on cold full builds.)
    function finalize(bytes calldata pk, uint256[512] calldata flatWords)
        external
        returns (address pointer)
    {
        if (pk.length != PUBLIC_KEY_LENGTH) revert BadKeyLength(pk.length);
        bytes32 pkHash = keccak256(pk);
        Setup storage s = setups[pkHash];
        if (!s.started) revert NotStarted(pkHash);
        if (bytes32(pk[0:32]) != s.rho) revert RhoMismatch(s.rho, bytes32(pk[0:32]));
        if (s.done != uint16((uint256(1) << ENTRIES) - 1)) revert NotFinished(pkHash, s.done);
        if (_pointers[pkHash] != address(0)) revert AlreadyFinalized(pkHash);

        uint256[][][] memory aHat = _assemble(flatWords, pkHash);
        bytes memory tr = trOf(pk);
        uint256[][] memory t1 = unpackT1(pk);
        // checks-effects-interactions: predict the CREATE2 address from the
        // assembled arguments, bind it, THEN deploy — so a future PKContract
        // revision with a constructor callback cannot observe an unbound
        // state, and the determinism claim is asserted, not assumed.
        pointer = _predictedAddress(aHat, tr, t1);
        _pointers[pkHash] = pointer;
        address deployed = address(new PKContract{salt: bytes32(0)}(aHat, tr, t1));
        assert(deployed == pointer);
        emit SetupFinalized(pkHash, pointer);
    }

    function expandedKey(bytes32 pkHash) public view returns (address) {
        return _pointers[pkHash];
    }

    function entriesDone(bytes32 pkHash) external view returns (uint256) {
        return setups[pkHash].done;
    }

    /// @notice Address the `PKContract` for `pk` is or would be deployed at
    ///         (CREATE2 in this registry, salt zero), given the candidate
    ///         `flatWords` (512 words, entry e at `32*e`) for the pinned
    ///         rho. Every entry is checked
    ///         against its staged per-entry hash, so a wrong word set
    ///         reverts (`EntryWordsMismatch`) rather than predicting a
    ///         phantom address — meaningful only once the entries are
    ///         staged (an unstaged key reverts the same way). Useful to
    ///         auditors before `finalize`.
    function pointerFor(bytes calldata pk, uint256[512] calldata flatWords)
        public
        view
        returns (address)
    {
        if (pk.length != PUBLIC_KEY_LENGTH) revert BadKeyLength(pk.length);
        bytes32 pkHash = keccak256(pk);
        uint256[][][] memory aHat = _assemble(flatWords, pkHash);
        return _predictedAddress(aHat, trOf(pk), unpackT1(pk));
    }

    /// @dev Assemble the matrix from the calldata words, checking every
    ///      entry against its staged per-entry hash. View-safe. Kept flat and
    ///      split per entry so no frame holds more than a handful of locals —
    ///      the legacy (non-via-ir) codegen overflows the EVM stack otherwise.
    function _assemble(uint256[512] calldata flatWords, bytes32 pkHash)
        private
        view
        returns (uint256[][][] memory aHat)
    {
        aHat = new uint256[][][](K);
        for (uint256 i = 0; i < K; i++) {
            aHat[i] = new uint256[][](L);
            for (uint256 j = 0; j < L; j++) {
                aHat[i][j] = _checkedEntry(flatWords, pkHash, i * L + j);
            }
        }
    }

    /// @dev The 32 words of entry `e` (at `flatWords[32*e .. 32*e+31]`),
    ///      reverted unless they hash to the staged commitment. The hash uses
    ///      the same encodePacked as `stage` (flat uint256 words, no length
    ///      prefix) — see the note there.
    function _checkedEntry(uint256[512] calldata flatWords, bytes32 pkHash, uint256 e)
        private
        view
        returns (uint256[] memory words)
    {
        words = new uint256[](32);
        for (uint256 w = 0; w < 32; w++) {
            words[w] = flatWords[32 * e + w];
        }
        bytes32 given = keccak256(abi.encodePacked(words));
        if (given != entryHashes[pkHash][e]) {
            revert EntryWordsMismatch(e, entryHashes[pkHash][e], given);
        }
    }

    /// @dev The CREATE2 address `new PKContract{salt: 0}(aHat, tr, t1)` lands
    ///      at in this registry. The encoding must byte-match the compiler's
    ///      argument encoding for the deploy above.
    function _predictedAddress(uint256[][][] memory aHat, bytes memory tr, uint256[][] memory t1)
        private
        view
        returns (address)
    {
        bytes32 initHash = keccak256(abi.encodePacked(type(PKContract).creationCode, abi.encode(aHat, tr, t1)));
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), bytes32(0), initHash)))));
    }

    /// @notice FIPS 204 `tr = H(pk, 64)`, H = SHAKE256, via the vendored sponge
    ///         (the same one the verifier hashes `mu` with).
    function trOf(bytes calldata pk) public pure returns (bytes memory) {
        CtxShake memory ctx;
        ctx = shakeUpdate(ctx, pk);
        return shakeDigest(ctx, TR_LENGTH);
    }

    /// @notice `t1` from the key bytes (`pk = rho(32) || t1` packed 10 bits per
    ///         coefficient, FIPS 204 Algorithm 22), in the ZKNOX compact
    ///         layout: K polynomials of 32 words, 8 x 32-bit coefficients
    ///         per word.
    function unpackT1(bytes calldata pk) public pure returns (uint256[][] memory t1) {
        bytes memory packed = pk[32:];
        t1 = new uint256[][](K);
        for (uint256 i = 0; i < K; i++) {
            uint256[] memory coeffs = bitUnpackAtOffset(packed, T1_BITS, i * N * T1_BITS, N);
            uint256[] memory words = new uint256[](32);
            for (uint256 w = 0; w < 32; w++) {
                uint256 acc = 0;
                for (uint256 j = 0; j < 8; j++) {
                    acc |= coeffs[8 * w + j] << (32 * j);
                }
                words[w] = acc;
            }
            t1[i] = words;
        }
    }
}