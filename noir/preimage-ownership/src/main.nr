// Ownership of a commitment-bound stealth account by knowledge of the spending
// secret (D-025). The key-exchange scheme (D-024) publishes
//
//     spend_key  = keccak256("pq-stealth/preimage/key/v0" || sk)          (in the meta-address)
//     opener     = SHA-256("pq-stealth/preimage/open/v0" || ss)            (per payment, from the KEM)
//     commitment = keccak256("pq-stealth/preimage/commit/v0" || spend_key || opener)
//
// and the stealth account is CREATE2-bound to `commitment`. Spending proves
//
//     I know (sk, opener) with keccak256(COMMIT || keccak256(KEY || sk) || opener) == commitment
//
// with `message` (the frame tx sig_hash, TXPARAM 0x08) and `commitment` as the
// public inputs, in the same [message_hi, message_lo, commitment_hi,
// commitment_lo] layout as noir/sphincs-c13-verify, so `Stealth8141ZkAccount`
// verifies either statement unchanged. The proof is bound to `message` because
// public inputs are part of the verified statement (they enter the transcript
// and the permutation argument's public-input delta); the circuit does not need
// to hash it again.
//
// Two keccak calls, about 80k UltraHonk gates: provable in a browser with
// bb.js in seconds. No signature, no signer state; the secret is never revealed
// and every spend is unlinkable to the others.

use keccak256::keccak256;

global KEY_DOMAIN_LEN: u32 = 26;
global OPEN_DOMAIN_LEN: u32 = 27; // used off-circuit only; recorded for the record
global COMMIT_DOMAIN_LEN: u32 = 29;

fn field_pair_to_bytes(hi: Field, lo: Field) -> [u8; 32] {
    let h: [u8; 16] = hi.to_be_bytes();
    let l: [u8; 16] = lo.to_be_bytes();
    let mut o: [u8; 32] = [0; 32];
    for i in 0..16 {
        o[i] = h[i];
        o[16 + i] = l[i];
    }
    o
}

fn main(
    message_hi: pub Field,
    message_lo: pub Field,
    commitment_hi: pub Field,
    commitment_lo: pub Field,
    sk: [u8; 32],
    opener: [u8; 32],
) {
    // range-check the public halves (to_be_bytes::<16> constrains < 2^128)
    let _message = field_pair_to_bytes(message_hi, message_lo);
    let commitment = field_pair_to_bytes(commitment_hi, commitment_lo);

    // spend_key = keccak256(KEY_DOMAIN || sk)
    let key_domain: [u8; KEY_DOMAIN_LEN] = "pq-stealth/preimage/key/v0".as_bytes();
    let mut kbuf: [u8; 58] = [0; 58];
    for i in 0..KEY_DOMAIN_LEN {
        kbuf[i] = key_domain[i];
    }
    for i in 0..32 {
        kbuf[KEY_DOMAIN_LEN + i] = sk[i];
    }
    let spend_key = keccak256(kbuf, 58);

    // commitment = keccak256(COMMIT_DOMAIN || spend_key || opener)
    let commit_domain: [u8; COMMIT_DOMAIN_LEN] = "pq-stealth/preimage/commit/v0".as_bytes();
    let mut cbuf: [u8; 93] = [0; 93];
    for i in 0..COMMIT_DOMAIN_LEN {
        cbuf[i] = commit_domain[i];
    }
    for i in 0..32 {
        cbuf[COMMIT_DOMAIN_LEN + i] = spend_key[i];
        cbuf[COMMIT_DOMAIN_LEN + 32 + i] = opener[i];
    }
    let c = keccak256(cbuf, 93);
    assert(c == commitment);
    assert(OPEN_DOMAIN_LEN == 27);
}
