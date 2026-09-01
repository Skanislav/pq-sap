// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SSTORE2} from "solady/utils/SSTORE2.sol";

/// @title StealthKeyRegistry
/// @notice Append-only registry of ML-KEM viewing (encapsulation) keys,
///         referenced by index from the 65-byte compact meta-address:
///
///             compact = spend_pub(33, SEC1 compressed) || index(32)
///
///         The secp256k1 spending key rides INLINE (its first byte is the
///         version/parity prefix 0x02/0x03), so the registry can only
///         break detection, never redirect funds: a swapped viewing key
///         denies scanning, but every derived stealth address is still
///         P = K + t*G under the pinned spending key.
///
///         Keys are stored as contract code (SSTORE2) — write once,
///         cheap EXTCODECOPY reads for senders resolving an index.
contract StealthKeyRegistry {
    event ViewingKeyRegistered(
        uint256 indexed index, address indexed registrant, uint256 length);

    address[] private _pointers;

    /// @notice Store a viewing key; returns its permanent index.
    function register(bytes calldata viewingKey) external returns (uint256 index) {
        address pointer = SSTORE2.write(viewingKey);
        _pointers.push(pointer);
        index = _pointers.length - 1;
        emit ViewingKeyRegistered(index, msg.sender, viewingKey.length);
    }

    /// @notice Resolve an index to the registered viewing key.
    function viewingKeyOf(uint256 index) external view returns (bytes memory) {
        return SSTORE2.read(_pointers[index]);
    }

    function count() external view returns (uint256) {
        return _pointers.length;
    }
}
