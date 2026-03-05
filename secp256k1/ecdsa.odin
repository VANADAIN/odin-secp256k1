package secp256k1

import "core:math/big"

// ECDSA operations for secp256k1: sign, verify, and recover (ecrecover).

ECDSA_Error :: enum {
	None,
	Invalid_Private_Key,
	Invalid_Signature,
	Invalid_Recovery_Id,
	Invalid_Public_Key,
	Signing_Failed,
	Recovery_Failed,
	Field_Error,
	Big_Error,
	RFC6979_Error,
}

Signature :: struct {
	r: big.Int,
	s: big.Int,
	v: u8, // recovery id (0 or 1)
}

signature_destroy :: proc(sig: ^Signature) {
	big.destroy(&sig.r, &sig.s)
}

// Helper: compare two big.Ints, return just the ordering (-1, 0, 1).
_cmp :: proc(a, b: ^big.Int) -> int {
	result, _ := big.cmp(a, b)
	return result
}

// Sign a 32-byte message hash with a private key using ECDSA.
// Returns (r, s, v) where v is the recovery id.
// Uses RFC 6979 for deterministic k generation.
sign :: proc(sig: ^Signature, privkey: ^big.Int, msg_hash: [32]u8, params: ^Curve_Params) -> ECDSA_Error {
	// Validate private key: 1 <= privkey < n
	one: big.Int
	defer big.destroy(&one)
	big.set(&one, 1)

	if _cmp(privkey, &one) == -1 || _cmp(privkey, &params.n) != -1 do return .Invalid_Private_Key

	// Convert private key to 32 bytes
	privkey_bytes: [32]u8
	if big.int_to_bytes_big(privkey, privkey_bytes[:]) != nil do return .Big_Error

	// Generate deterministic k via RFC 6979
	k: big.Int
	defer big.destroy(&k)
	if generate_k(&k, privkey_bytes, msg_hash, &params.n) != .None do return .RFC6979_Error

	// Compute R = k * G
	r_point: Point
	defer point_destroy(&r_point)

	g: Point
	defer point_destroy(&g)
	big.set(&g.x, &params.gx)
	big.set(&g.y, &params.gy)

	if scalar_mul_point(&r_point, &k, &g, params) != .None do return .Signing_Failed
	if point_is_infinity(&r_point) do return .Signing_Failed

	// r = R.x mod n
	if big.mod(&sig.r, &r_point.x, &params.n) != nil do return .Big_Error
	is_r_zero, _ := big.is_zero(&sig.r)
	if is_r_zero do return .Signing_Failed

	// Recovery id: 0 if R.y is even, 1 if odd
	y_bit, _ := big.int_bitfield_extract_single(&r_point.y, 0)
	sig.v = u8(y_bit)

	// s = k^(-1) * (msg_hash + r * privkey) mod n
	z, r_priv, k_inv: big.Int
	defer big.destroy(&z, &r_priv, &k_inv)

	// z = msg_hash as big int
	msg_hash_copy := msg_hash
	if big.int_from_bytes_big(&z, msg_hash_copy[:]) != nil do return .Big_Error

	// r_priv = r * privkey mod n
	if big.mulmod(&r_priv, &sig.r, privkey, &params.n) != nil do return .Big_Error

	// z = z + r_priv mod n
	if big.addmod(&z, &z, &r_priv, &params.n) != nil do return .Big_Error

	// k_inv = k^(-1) mod n
	if scalar_inv(&k_inv, &k, &params.n) != .None do return .Field_Error

	// s = k_inv * z mod n
	if big.mulmod(&sig.s, &k_inv, &z, &params.n) != nil do return .Big_Error

	is_s_zero, _ := big.is_zero(&sig.s)
	if is_s_zero do return .Signing_Failed

	// Enforce low-S: if s > n/2, set s = n - s and flip v
	half_n: big.Int
	defer big.destroy(&half_n)
	two: big.Int
	defer big.destroy(&two)
	big.set(&two, 2)
	if big.div(&half_n, &params.n, &two) != nil do return .Big_Error

	if _cmp(&sig.s, &half_n) == 1 {
		if big.sub(&sig.s, &params.n, &sig.s) != nil do return .Big_Error
		sig.v ~= 1 // flip recovery id
	}

	return .None
}

// Verify an ECDSA signature against a public key and message hash.
verify :: proc(pubkey: ^Point, msg_hash: [32]u8, sig: ^Signature, params: ^Curve_Params) -> ECDSA_Error {
	if point_is_infinity(pubkey) do return .Invalid_Public_Key

	one: big.Int
	defer big.destroy(&one)
	big.set(&one, 1)

	// Validate r: 1 <= r < n
	if _cmp(&sig.r, &one) == -1 || _cmp(&sig.r, &params.n) != -1 do return .Invalid_Signature
	// Validate s: 1 <= s < n
	if _cmp(&sig.s, &one) == -1 || _cmp(&sig.s, &params.n) != -1 do return .Invalid_Signature

	// z = msg_hash as big int
	z: big.Int
	defer big.destroy(&z)
	msg_hash_copy := msg_hash
	if big.int_from_bytes_big(&z, msg_hash_copy[:]) != nil do return .Big_Error

	// s_inv = s^(-1) mod n
	s_inv: big.Int
	defer big.destroy(&s_inv)
	if scalar_inv(&s_inv, &sig.s, &params.n) != .None do return .Field_Error

	// u1 = z * s_inv mod n
	u1: big.Int
	defer big.destroy(&u1)
	if big.mulmod(&u1, &z, &s_inv, &params.n) != nil do return .Big_Error

	// u2 = r * s_inv mod n
	u2: big.Int
	defer big.destroy(&u2)
	if big.mulmod(&u2, &sig.r, &s_inv, &params.n) != nil do return .Big_Error

	// R' = u1 * G + u2 * pubkey
	g: Point
	defer point_destroy(&g)
	big.set(&g.x, &params.gx)
	big.set(&g.y, &params.gy)

	p1, p2, r_prime: Point
	defer point_destroy(&p1, &p2, &r_prime)

	if scalar_mul_point(&p1, &u1, &g, params) != .None do return .Field_Error
	if scalar_mul_point(&p2, &u2, pubkey, params) != .None do return .Field_Error
	if point_add(&r_prime, &p1, &p2, params) != .None do return .Field_Error

	if point_is_infinity(&r_prime) do return .Invalid_Signature

	// Check: r == R'.x mod n
	rx_mod_n: big.Int
	defer big.destroy(&rx_mod_n)
	if big.mod(&rx_mod_n, &r_prime.x, &params.n) != nil do return .Big_Error

	eq, _ := big.equals(&rx_mod_n, &sig.r)
	if !eq do return .Invalid_Signature

	return .None
}

// Recover the public key from a signature and message hash (ecrecover).
// recovery_id is 0 or 1.
recover_pubkey :: proc(pubkey: ^Point, msg_hash: [32]u8, sig: ^Signature, recovery_id: u8, params: ^Curve_Params) -> ECDSA_Error {
	if recovery_id > 1 do return .Invalid_Recovery_Id

	one: big.Int
	defer big.destroy(&one)
	big.set(&one, 1)

	// Validate r and s
	if _cmp(&sig.r, &one) == -1 || _cmp(&sig.r, &params.n) != -1 do return .Invalid_Signature
	if _cmp(&sig.s, &one) == -1 || _cmp(&sig.s, &params.n) != -1 do return .Invalid_Signature

	// Reconstruct R point from r and recovery_id
	r_point: Point
	defer point_destroy(&r_point)
	big.set(&r_point.x, &sig.r)

	// Compute y² = x³ + 7 mod p
	y_sq, x3: big.Int
	defer big.destroy(&y_sq, &x3)
	fp := &params.p

	if big.sqrmod(&x3, &r_point.x, fp) != nil do return .Big_Error
	if big.mulmod(&x3, &x3, &r_point.x, fp) != nil do return .Big_Error
	if big.addmod(&y_sq, &x3, &params.b, fp) != nil do return .Big_Error

	// y = y_sq^((p+1)/4) mod p (since p ≡ 3 mod 4)
	exp: big.Int
	defer big.destroy(&exp)
	if big.add(&exp, fp, &one) != nil do return .Big_Error
	four: big.Int
	defer big.destroy(&four)
	big.set(&four, 4)
	if big.div(&exp, &exp, &four) != nil do return .Big_Error
	if field_pow(&r_point.y, &y_sq, &exp, fp) != .None do return .Recovery_Failed

	// Verify y² mod p == y_sq
	check: big.Int
	defer big.destroy(&check)
	if big.sqrmod(&check, &r_point.y, fp) != nil do return .Big_Error
	eq_check, _ := big.equals(&check, &y_sq)
	if !eq_check do return .Recovery_Failed

	// Select y parity based on recovery_id
	y_bit, _ := big.int_bitfield_extract_single(&r_point.y, 0)
	if u8(y_bit) != recovery_id {
		if big.sub(&r_point.y, fp, &r_point.y) != nil do return .Big_Error
	}
	r_point.is_inf = false

	// z = msg_hash as big int
	z: big.Int
	defer big.destroy(&z)
	msg_hash_copy := msg_hash
	if big.int_from_bytes_big(&z, msg_hash_copy[:]) != nil do return .Big_Error

	// r_inv = r^(-1) mod n
	r_inv: big.Int
	defer big.destroy(&r_inv)
	if scalar_inv(&r_inv, &sig.r, &params.n) != .None do return .Recovery_Failed

	// pubkey = r_inv * (s * R - z * G)
	g: Point
	defer point_destroy(&g)
	big.set(&g.x, &params.gx)
	big.set(&g.y, &params.gy)

	// s * R
	s_r: Point
	defer point_destroy(&s_r)
	if scalar_mul_point(&s_r, &sig.s, &r_point, params) != .None do return .Recovery_Failed

	// z * G
	z_g: Point
	defer point_destroy(&z_g)
	if scalar_mul_point(&z_g, &z, &g, params) != .None do return .Recovery_Failed

	// negate z_g: (-z_g).y = p - z_g.y
	if !point_is_infinity(&z_g) {
		if big.sub(&z_g.y, fp, &z_g.y) != nil do return .Big_Error
	}

	// s_r + (-z_g)
	sum_pt: Point
	defer point_destroy(&sum_pt)
	if point_add(&sum_pt, &s_r, &z_g, params) != .None do return .Recovery_Failed

	// pubkey = r_inv * sum
	if scalar_mul_point(pubkey, &r_inv, &sum_pt, params) != .None do return .Recovery_Failed

	if point_is_infinity(pubkey) do return .Recovery_Failed
	return .None
}
