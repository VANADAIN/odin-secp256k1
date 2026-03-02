package secp256k1

import "core:math/big"

// Finite field Fp arithmetic (mod p) for secp256k1.

Field_Error :: enum {
	None,
	Big_Error,
	Zero_Inverse,
}

// result = (a + b) mod p
field_add :: proc(result, a, b, p: ^big.Int) -> Field_Error {
	if big.addmod(result, a, b, p) != nil do return .Big_Error
	return .None
}

// result = (a - b) mod p
field_sub :: proc(result, a, b, p: ^big.Int) -> Field_Error {
	if big.submod(result, a, b, p) != nil do return .Big_Error
	return .None
}

// result = (a * b) mod p
field_mul :: proc(result, a, b, p: ^big.Int) -> Field_Error {
	if big.mulmod(result, a, b, p) != nil do return .Big_Error
	return .None
}

// result = a^(-1) mod p  (via Fermat's little theorem: a^(p-2) mod p)
// Returns Zero_Inverse if a == 0.
field_inv :: proc(result, a, p: ^big.Int) -> Field_Error {
	is_z, _ := big.is_zero(a)
	if is_z do return .Zero_Inverse

	// exp = p - 2
	two, exp: big.Int
	defer big.destroy(&two, &exp)
	big.set(&two, 2)
	if big.sub(&exp, p, &two) != nil do return .Big_Error

	return field_pow(result, a, &exp, p)
}

// result = (a ^ exp) mod p
// Square-and-multiply algorithm.
field_pow :: proc(result, base, exp, p: ^big.Int) -> Field_Error {
	is_z, _ := big.is_zero(exp)
	if is_z {
		big.set(result, 1)
		return .None
	}

	acc: big.Int
	defer big.destroy(&acc)
	big.set(&acc, 1)

	nbits, cerr := big.count_bits(exp)
	if cerr != nil do return .Big_Error

	for i := nbits - 1; i >= 0; i -= 1 {
		// acc = acc² mod p
		if big.sqrmod(&acc, &acc, p) != nil do return .Big_Error

		// if bit i of exp is set: acc = acc * base mod p
		bit, berr := big.int_bitfield_extract_single(exp, i)
		if berr != nil do return .Big_Error

		if bit == 1 {
			if big.mulmod(&acc, &acc, base, p) != nil do return .Big_Error
		}
	}

	if big.set(result, &acc) != nil do return .Big_Error
	return .None
}

// result = (-a) mod p  =>  (p - a) mod p
field_neg :: proc(result, a, p: ^big.Int) -> Field_Error {
	is_z, _ := big.is_zero(a)
	if is_z {
		big.set(result, 0)
		return .None
	}
	if big.sub(result, p, a) != nil do return .Big_Error
	return .None
}
