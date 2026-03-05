package secp256k1

import "core:math/big"

// Scalar field Fn arithmetic (mod n) and scalar multiplication for secp256k1.

Scalar_Error :: enum {
	None,
	Field_Error,
	Invalid_Scalar,
}

// result = (a + b) mod n
scalar_add :: proc(result, a, b, n: ^big.Int) -> Scalar_Error {
	if big.addmod(result, a, b, n) != nil do return .Field_Error
	return .None
}

// result = (a - b) mod n
scalar_sub :: proc(result, a, b, n: ^big.Int) -> Scalar_Error {
	if big.submod(result, a, b, n) != nil do return .Field_Error
	return .None
}

// result = (a * b) mod n
scalar_mul :: proc(result, a, b, n: ^big.Int) -> Scalar_Error {
	if big.mulmod(result, a, b, n) != nil do return .Field_Error
	return .None
}

// result = a^(-1) mod n  (via Fermat's little theorem: a^(n-2) mod n)
scalar_inv :: proc(result, a, n: ^big.Int) -> Scalar_Error {
	is_z, _ := big.is_zero(a)
	if is_z do return .Invalid_Scalar

	two, exp: big.Int
	defer big.destroy(&two, &exp)
	big.set(&two, 2)
	if big.sub(&exp, n, &two) != nil do return .Field_Error

	if field_pow(result, a, &exp, n) != .None do return .Field_Error
	return .None
}

// result = k * P  (double-and-add scalar multiplication)
// k must be in range [1, n-1].
scalar_mul_point :: proc(result: ^Point, k: ^big.Int, p: ^Point, params: ^Curve_Params) -> Scalar_Error {
	is_z, _ := big.is_zero(k)
	if is_z {
		result^ = point_infinity()
		return .None
	}

	nbits, cerr := big.count_bits(k)
	if cerr != nil do return .Field_Error

	// Initialize result to infinity
	result^ = point_infinity()

	tmp: Point
	defer point_destroy(&tmp)

	for i := nbits - 1; i >= 0; i -= 1 {
		// result = 2 * result
		point_copy(&tmp, result)
		if point_double(result, &tmp, params) != .None do return .Field_Error

		// if bit i of k is set: result = result + P
		bit, berr := big.int_bitfield_extract_single(k, i)
		if berr != nil do return .Field_Error

		if bit == 1 {
			point_copy(&tmp, result)
			if point_add(result, &tmp, p, params) != .None do return .Field_Error
		}
	}

	return .None
}

// Generate public key from private key: pubkey = privkey * G
privkey_to_pubkey :: proc(pubkey: ^Point, privkey: ^big.Int, params: ^Curve_Params) -> Scalar_Error {
	g: Point
	defer point_destroy(&g)
	big.set(&g.x, &params.gx)
	big.set(&g.y, &params.gy)

	return scalar_mul_point(pubkey, privkey, &g, params)
}
