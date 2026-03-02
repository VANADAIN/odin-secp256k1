package secp256k1

import "core:math/big"

// secp256k1 curve: y² = x³ + 7 (mod p)
//
// Parameters from SEC 2: https://www.secg.org/sec2-v2.pdf

// Field prime: p = 2^256 - 2^32 - 977
P_HEX :: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"

// Curve coefficients
A_VALUE :: 0 // a = 0
B_VALUE :: 7 // b = 7

// Generator point G
GX_HEX :: "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
GY_HEX :: "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"

// Group order
N_HEX :: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

// Cofactor
H_VALUE :: 1

// Curve_Params holds initialized big.Int values for the curve.
// Call init_curve_params() before use and destroy_curve_params() when done.
Curve_Params :: struct {
	p:  big.Int, // field prime
	a:  big.Int, // curve coefficient a (= 0)
	b:  big.Int, // curve coefficient b (= 7)
	gx: big.Int, // generator x
	gy: big.Int, // generator y
	n:  big.Int, // group order
	h:  big.Int, // cofactor
}

Params_Error :: enum {
	None,
	Parse_Failed,
}

init_curve_params :: proc(params: ^Curve_Params) -> Params_Error {
	if big.atoi(&params.p, P_HEX, 16) != nil do return .Parse_Failed
	if big.atoi(&params.n, N_HEX, 16) != nil do return .Parse_Failed
	if big.atoi(&params.gx, GX_HEX, 16) != nil do return .Parse_Failed
	if big.atoi(&params.gy, GY_HEX, 16) != nil do return .Parse_Failed

	big.set(&params.a, A_VALUE)
	big.set(&params.b, B_VALUE)
	big.set(&params.h, H_VALUE)

	return .None
}

destroy_curve_params :: proc(params: ^Curve_Params) {
	big.destroy(&params.p)
	big.destroy(&params.a)
	big.destroy(&params.b)
	big.destroy(&params.gx)
	big.destroy(&params.gy)
	big.destroy(&params.n)
	big.destroy(&params.h)
}
