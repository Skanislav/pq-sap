// SPHINCS- C13 signature verification in-circuit, with the public key hidden
// behind the D-018 commitment.
//
// Port of js-client/contracts/src/vendor/sphincs-minus/SPHINCs-C13Asm.sol
// (parameters n=16 h=22 d=2 a=19 k=7 w=8 l=43 target_sum=208, sig 3,688 B,
// keccak256 tweakable hash, FIPS 205 uncompressed 32-byte ADRS).
//
// Statement: I know (pkSeed, pkRoot, opener, sig) such that
//   commitment == keccak256("pq-stealth/sphincs-c13/commit/v0" || pkSeed16 || pkRoot16 || opener)
//   and sig is a valid C13 signature over `message` under (pkSeed, pkRoot).
// Public inputs: message (the frame tx sig_hash) and the commitment, each as
// two 128-bit field elements. Nothing about the key leaks, which is what makes
// a SPHINCS- spend unlinkable (D-018 open item) - the direct 188k verifier
// reveals the key.
//
// Circuit-shape notes (see docs/research/zk-sphincs-frames.md):
// * every n=16 value is a 32-byte top-aligned word in preimages, as in the Yul;
//   the WOTS counter is the one right-aligned value.
// * the two soundness checks (forced-zero FORS index, WOTS+C digit sum) are
//   assertions, not early exits.
// * WOTS chain lengths are data-dependent, but WOTS+C fixes the total at
//   L*7 - 208 = 93 steps per layer. The prover supplies `chain_hint`, the chain
//   each of the 93 steps belongs to; the circuit checks each chain receives
//   exactly 7 - digit steps and hashes them in order. Same 335 keccak calls as
//   the Solidity verifier instead of 43*7 unconditional chains.

use keccak256::keccak256;

global N_ELEM: u32 = 16;
global SUB_H: u32 = 11;
global TARGET_SUM: u32 = 208;
global STEPS: u32 = 93; // L*(w-1) - TARGET_SUM
global SIG_LEN: u32 = 3688;
global HT_START: u32 = 1952; // 128 + 6*19*16

fn mask(x: [u8; 32]) -> [u8; 32] {
    let mut o = x;
    for i in 16..32 {
        o[i] = 0;
    }
    o
}

fn put_u32(a: [u8; 32], off: u32, x: u32) -> [u8; 32] {
    let mut o = a;
    o[off] = ((x >> 24) & 0xff) as u8;
    o[off + 1] = ((x >> 16) & 0xff) as u8;
    o[off + 2] = ((x >> 8) & 0xff) as u8;
    o[off + 3] = (x & 0xff) as u8;
    o
}

/// FIPS 205 Sec. 4.2 uncompressed ADRS: layer || tree(96 bit) || type || w1 || w2 || w3.
fn adrs(layer: u32, tree: u32, typ: u32, w1: u32, w2: u32, w3: u32) -> [u8; 32] {
    let mut a: [u8; 32] = [0; 32];
    a = put_u32(a, 0, layer);
    a = put_u32(a, 12, tree); // tree address fits 32 bits here (idxTree <= 2^11)
    a = put_u32(a, 16, typ);
    a = put_u32(a, 20, w1);
    a = put_u32(a, 24, w2);
    a = put_u32(a, 28, w3);
    a
}

/// keccak256(seed || adrs || p)[0:16] as a top-aligned word.
fn th1(seed: [u8; 32], a: [u8; 32], p: [u8; 32]) -> [u8; 32] {
    let mut b: [u8; 96] = [0; 96];
    for i in 0..32 {
        b[i] = seed[i];
        b[32 + i] = a[i];
        b[64 + i] = p[i];
    }
    mask(keccak256(b, 96))
}

/// keccak256(seed || adrs || left || right)[0:16].
fn th2(seed: [u8; 32], a: [u8; 32], l: [u8; 32], r: [u8; 32]) -> [u8; 32] {
    let mut b: [u8; 128] = [0; 128];
    for i in 0..32 {
        b[i] = seed[i];
        b[32 + i] = a[i];
        b[64 + i] = l[i];
        b[96 + i] = r[i];
    }
    mask(keccak256(b, 128))
}

/// Merkle step with the branchless-swap semantics of the Yul: odd index puts
/// the node on the right.
fn merkle_step(seed: [u8; 32], a: [u8; 32], node: [u8; 32], sibling: [u8; 32], odd: bool) -> [u8; 32] {
    let l = if odd { sibling } else { node };
    let r = if odd { node } else { sibling };
    th2(seed, a, l, r)
}

/// Bits [shift, shift+NB) of a big-endian 256-bit digest, as an integer.
fn bits<let NB: u32>(d: [u8; 32], shift: u32) -> u32 {
    let mut v: u32 = 0;
    for i in 0..NB {
        let p = shift + i;
        let byte = d[31 - (p / 8)];
        let bit = ((byte >> ((p % 8) as u8)) & 1) as u32;
        v = v + (bit << i);
    }
    v
}

/// 16-byte signature element at byte offset `off`, top-aligned.
fn elem(sig: [u8; SIG_LEN], off: u32) -> [u8; 32] {
    let mut o: [u8; 32] = [0; 32];
    for i in 0..N_ELEM {
        o[i] = sig[off + i];
    }
    o
}

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
    pk_seed: [u8; 16],
    pk_root: [u8; 16],
    opener: [u8; 32],
    sig: [u8; SIG_LEN],
    chain_hint: [[u8; STEPS]; 2],
) {
    let message = field_pair_to_bytes(message_hi, message_lo);
    let commitment = field_pair_to_bytes(commitment_hi, commitment_lo);

    // --- commitment = keccak256(domain || pk || opener), pk = pkSeed16 || pkRoot16 ---
    let domain: [u8; 32] = "pq-stealth/sphincs-c13/commit/v0".as_bytes();
    let mut cbuf: [u8; 96] = [0; 96];
    for i in 0..32 {
        cbuf[i] = domain[i];
        cbuf[64 + i] = opener[i];
    }
    for i in 0..16 {
        cbuf[32 + i] = pk_seed[i];
        cbuf[48 + i] = pk_root[i];
    }
    let c = keccak256(cbuf, 96);
    assert(c == commitment);

    // top-aligned 32-byte forms (the verifier's canonical key check holds by construction)
    let mut seed: [u8; 32] = [0; 32];
    let mut root: [u8; 32] = [0; 32];
    for i in 0..16 {
        seed[i] = pk_seed[i];
        root[i] = pk_root[i];
    }

    // --- H_msg = keccak256(seed || root || R || message || 0xFF*32) ---
    let r = elem(sig, 0);
    let mut hbuf: [u8; 160] = [0; 160];
    for i in 0..32 {
        hbuf[i] = seed[i];
        hbuf[32 + i] = root[i];
        hbuf[64 + i] = r[i];
        hbuf[96 + i] = message[i];
        hbuf[128 + i] = 0xff;
    }
    let digest = keccak256(hbuf, 160);

    let ht_idx = bits::<22>(digest, 133);
    // FORS+C forced zero: the last FORS index must be 0
    assert(bits::<19>(digest, 114) == 0);

    let idx_leaf0 = ht_idx & 0x7ff;
    let idx_tree0 = ht_idx >> 11;

    // --- FORS: 6 trees with auth paths + 1 forced-zero leaf, then compress ---
    let mut roots: [[u8; 32]; 7] = [[0; 32]; 7];
    for i in 0..6 {
        let tree_idx = bits::<19>(digest, 19 * i);
        let secret = elem(sig, 16 + 16 * i);
        let mut node = th1(seed, adrs(0, idx_tree0, 3, idx_leaf0, 0, (i << 19) | tree_idx), secret);
        let mut path_idx = tree_idx;
        let auth = 128 + 304 * i;
        for h in 0..19 {
            let sibling = elem(sig, auth + 16 * h);
            let parent = path_idx >> 1;
            let a = adrs(0, idx_tree0, 3, idx_leaf0, h + 1, (i << (18 - h)) | parent);
            node = merkle_step(seed, a, node, sibling, (path_idx & 1) == 1);
            path_idx = parent;
        }
        roots[i] = node;
    }
    {
        let last = elem(sig, 16 + 16 * 6);
        roots[6] = th1(seed, adrs(0, idx_tree0, 3, idx_leaf0, 0, 6 << 19), last);
    }
    let mut fbuf: [u8; 288] = [0; 288];
    {
        let a = adrs(0, idx_tree0, 4, idx_leaf0, 0, 0);
        for i in 0..32 {
            fbuf[i] = seed[i];
            fbuf[32 + i] = a[i];
        }
        for t in 0..7 {
            for i in 0..32 {
                fbuf[64 + 32 * t + i] = roots[t][i];
            }
        }
    }
    let mut current = mask(keccak256(fbuf, 288));

    // --- hypertree: 2 layers of WOTS+C + 11-level Merkle ---
    let mut idx_tree = ht_idx;
    let mut sig_off = HT_START;
    for layer in 0..2 {
        let idx_leaf = idx_tree & 0x7ff;
        idx_tree = idx_tree >> 11;
        let count_off = sig_off + 688;

        // WOTS message digest: keccak(seed || WOTS_HASH adrs || current || uint256(count))
        let wots_adrs = adrs(layer, idx_tree, 0, idx_leaf, 0, 0);
        let mut dbuf: [u8; 128] = [0; 128];
        for i in 0..32 {
            dbuf[i] = seed[i];
            dbuf[32 + i] = wots_adrs[i];
            dbuf[64 + i] = current[i];
        }
        for i in 0..4 {
            dbuf[124 + i] = sig[count_off + i]; // right-aligned counter
        }
        let d = keccak256(dbuf, 128);

        // digits and the WOTS+C constant-sum check
        let mut digits: [u32; 43] = [0; 43];
        let mut sum: u32 = 0;
        for i in 0..43 {
            digits[i] = bits::<3>(d, 3 * i);
            sum = sum + digits[i];
        }
        assert(sum == TARGET_SUM);

        // chains: 93 hint-driven steps
        let mut vals: [[u8; 32]; 43] = [[0; 32]; 43];
        for i in 0..43 {
            vals[i] = elem(sig, sig_off + 16 * i);
        }
        let mut pos: [u32; 43] = [0; 43];
        let hint = chain_hint[layer];
        for s in 0..STEPS {
            let ch = hint[s] as u32;
            assert(ch < 43);
            let dg = digits[ch];
            let p = pos[ch];
            let a = adrs(layer, idx_tree, 0, idx_leaf, ch, dg + p);
            vals[ch] = th1(seed, a, vals[ch]);
            pos[ch] = p + 1;
        }
        for i in 0..43 {
            assert(pos[i] == 7 - digits[i]);
        }

        // WOTS_PK = keccak(seed || WOTS_PK adrs || 43 chain ends)
        let mut pbuf: [u8; 1440] = [0; 1440];
        {
            let a = adrs(layer, idx_tree, 1, idx_leaf, 0, 0);
            for i in 0..32 {
                pbuf[i] = seed[i];
                pbuf[32 + i] = a[i];
            }
            for t in 0..43 {
                for i in 0..32 {
                    pbuf[64 + 32 * t + i] = vals[t][i];
                }
            }
        }
        let mut node = mask(keccak256(pbuf, 1440));

        // TREE auth path, 11 levels: type 2, word1 = 0
        let auth_off = count_off + 4;
        let mut m_idx = idx_leaf;
        for h in 0..SUB_H {
            let sibling = elem(sig, auth_off + 16 * h);
            let parent = m_idx >> 1;
            let a = adrs(layer, idx_tree, 2, 0, h + 1, parent);
            node = merkle_step(seed, a, node, sibling, (m_idx & 1) == 1);
            m_idx = parent;
        }
        current = node;
        sig_off = auth_off + 176;
    }

    assert(current == root);
}
