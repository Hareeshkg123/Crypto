from pathlib import Path

cipher = Path("flag.enc").read_bytes()
print("Cipher length:", len(cipher))

known_plain = bytes.fromhex(
    "89504E470D0A1A0A" 
    "0000000D49484452"  
)

# First 16 bytes of keystream from known plaintext
keystream_prefix = bytes(c ^ p for c, p in zip(cipher[:16], known_plain))
print("Derived first 16 keystream bytes:", keystream_prefix.hex())


R1_BITS = 12
R2_BITS = 19

R1_TAPS = [10, 5]
R2_TAPS = [14, 8]


def make_lfsr(bits: int, taps_lsb: list[int]):
    """
    Create a generator function that produces bytes from an LFSR.

    - bits      : length of the register (12 / 19)
    - taps_lsb  : tap positions, 0-based from LSB (rightmost bit)
    - Output bit: LSB
    - Shift     : right (new bit enters MSB)
    """
    taps_lsb = list(taps_lsb)

    def step(state: int):
        new_bit = 0
        for t in taps_lsb:
            new_bit ^= (state >> t) & 1

        out_bit = state & 1 
        state >>= 1
        state |= (new_bit << (bits - 1))
        state &= (1 << bits) - 1
        return state, out_bit

    def gen_bytes(seed: int, nbytes: int) -> bytes:
        state = seed
        out = bytearray()
        for _ in range(nbytes):
            b = 0
            for pos in range(8):
                state, bit = step(state)
                b |= (bit << pos)
            out.append(b)
        return bytes(out)

    return gen_bytes


gen_r1 = make_lfsr(R1_BITS, R1_TAPS)
gen_r2 = make_lfsr(R2_BITS, R2_TAPS)


def recover_seeds(prefix: bytes, n_bytes: int = 5):
    """
    prefix  : first bytes of PRNG output (from known plaintext)
    n_bytes : number of bytes used for matching in the attack
    """

    print("\n[*] Building table for Register 1...")
    r1_table: dict[bytes, list[int]] = {}

    for seed1 in range(1, 1 << R1_BITS):
        stream1 = gen_r1(seed1, n_bytes)
        r1_table.setdefault(stream1, []).append(seed1)

    print("    R1 sequences stored:", len(r1_table))

    print("[*] Scanning Register 2 states and matching...")
    candidates: list[tuple[int, int]] = []

    for seed2 in range(1, 1 << R2_BITS):
        stream2 = gen_r2(seed2, n_bytes)
        needed_r1 = bytes(
            (prefix[i] - stream2[i]) % 255 for i in range(n_bytes)
        )

        if needed_r1 in r1_table:
            for seed1 in r1_table[needed_r1]:
                candidates.append((seed1, seed2))

    print("    Candidate (R1, R2) pairs:", len(candidates))

    print("[*] Verifying candidates on full 16-byte prefix...")
    for seed1, seed2 in candidates:
        s1_full = gen_r1(seed1, len(prefix))
        s2_full = gen_r2(seed2, len(prefix))
        ks_full = bytes((a + b) % 255 for a, b in zip(s1_full, s2_full))
        if ks_full == prefix:
            print("    ✅ Seeds found!")
            print("       R1 seed =", seed1)
            print("       R2 seed =", seed2)
            return seed1, seed2

    raise RuntimeError("Failed to recover seeds – something is inconsistent.")


r1_seed, r2_seed = recover_seeds(keystream_prefix, n_bytes=5)

print("\n[*] Generating full keystream and decrypting...")

r1_full = gen_r1(r1_seed, len(cipher))
r2_full = gen_r2(r2_seed, len(cipher))

keystream = bytes((a + b) % 255 for a, b in zip(r1_full, r2_full))

plaintext = bytes(c ^ k for c, k in zip(cipher, keystream))

out_path = Path("flag.png")
out_path.write_bytes(plaintext)

print("Done! Decrypted PNG saved as:", out_path)
print("First 16 bytes of plaintext:", plaintext[:16].hex())
