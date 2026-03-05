package secp256k1

import "core:crypto/hmac"
import "core:crypto/hash"
import "core:math/big"
import "core:mem"

// RFC 6979: Deterministic ECDSA nonce (k) generation using HMAC-SHA256.
// Reference: https://datatracker.ietf.org/doc/html/rfc6979

RFC6979_Error :: enum {
	None,
	Big_Error,
	Failed,
}

// Generate deterministic k for ECDSA signing.
// privkey: 32 bytes (big-endian private key)
// msg_hash: 32 bytes (hash of the message to sign)
// n: group order
// result: the generated k value
generate_k :: proc(result: ^big.Int, privkey_bytes: [32]u8, msg_hash: [32]u8, n: ^big.Int) -> RFC6979_Error {
	pk := privkey_bytes
	mh := msg_hash

	// Step b: V = 0x01 repeated (32 bytes)
	v: [32]u8
	mem.set(&v, 0x01, 32)

	// Step c: K = 0x00 repeated (32 bytes)
	k_hmac: [32]u8

	// Step d: K = HMAC_K(V || 0x00 || privkey || msg_hash)
	buf: [97]u8 // 32 + 1 + 32 + 32
	mem.copy(&buf[0], &v, 32)
	buf[32] = 0x00
	mem.copy(&buf[33], &pk, 32)
	mem.copy(&buf[65], &mh, 32)
	hmac.sum(hash.Algorithm.SHA256, k_hmac[:], buf[:], k_hmac[:])

	// Step e: V = HMAC_K(V)
	hmac.sum(hash.Algorithm.SHA256, v[:], v[:], k_hmac[:])

	// Step f: K = HMAC_K(V || 0x01 || privkey || msg_hash)
	mem.copy(&buf[0], &v, 32)
	buf[32] = 0x01
	mem.copy(&buf[33], &pk, 32)
	mem.copy(&buf[65], &mh, 32)
	hmac.sum(hash.Algorithm.SHA256, k_hmac[:], buf[:], k_hmac[:])

	// Step g: V = HMAC_K(V)
	hmac.sum(hash.Algorithm.SHA256, v[:], v[:], k_hmac[:])

	// Step h: loop until we find a valid k
	one: big.Int
	defer big.destroy(&one)
	big.set(&one, 1)

	for _ in 0 ..< 256 {
		// h.1: V = HMAC_K(V)
		hmac.sum(hash.Algorithm.SHA256, v[:], v[:], k_hmac[:])

		// h.2: T = V (for 256-bit curve, one iteration gives us 32 bytes)
		candidate: big.Int
		if big.int_from_bytes_big(&candidate, v[:]) != nil {
			big.destroy(&candidate)
			return .Big_Error
		}

		// h.3: Check if 1 <= candidate < n
		cmp_one, _ := big.cmp(&candidate, &one)
		cmp_n, _ := big.cmp(&candidate, n)
		if (cmp_one == 0 || cmp_one == 1) && cmp_n == -1 {
			if big.set(result, &candidate) != nil {
				big.destroy(&candidate)
				return .Big_Error
			}
			big.destroy(&candidate)
			return .None
		}
		big.destroy(&candidate)

		// k not suitable; update K and V
		buf_retry: [33]u8 // 32 + 1
		mem.copy(&buf_retry[0], &v, 32)
		buf_retry[32] = 0x00
		hmac.sum(hash.Algorithm.SHA256, k_hmac[:], buf_retry[:], k_hmac[:])
		hmac.sum(hash.Algorithm.SHA256, v[:], v[:], k_hmac[:])
	}

	return .Failed
}
